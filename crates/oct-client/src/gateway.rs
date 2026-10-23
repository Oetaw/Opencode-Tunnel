use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{CONNECTION, SEC_WEBSOCKET_PROTOCOL, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use futures_util::SinkExt;
use oct_protocol::httpwire::{validate_ws_subprotocol, MAX_SUBPROTOCOLS};
use oct_protocol::{ErrorCode, HttpRequestHead, OpenWs, WsOpcode, MAX_WS_MESSAGE};
use oct_transport::{Inbound, Mux, Stream, TransportError};
use tokio::sync::watch;

use crate::auth::{authenticate, AuthMiddlewareState, AuthState};

const RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct GatewayState {
    pub mux: watch::Receiver<Option<Mux>>,
    pub port: u16,
}

pub(crate) fn build_router(state: GatewayState, auth: AuthState) -> Router {
    let middleware_state = AuthMiddlewareState {
        auth: std::sync::Arc::new(auth),
        port: state.port,
    };
    Router::new()
        .route("/", any(gateway_handler))
        .route("/{*path}", any(gateway_handler))
        .fallback(gateway_handler)
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            middleware_state,
            authenticate,
        ))
}

async fn gateway_handler(State(state): State<GatewayState>, request: Request) -> Response<Body> {
    if has_websocket_upgrade(request.headers()) {
        return gateway_websocket(state, request).await;
    }

    let mux = state.mux.borrow().clone();
    let Some(mux) = mux.filter(|mux| !mux.is_closed()) else {
        return host_offline();
    };

    let method = request.method().clone();
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_owned();
    let headers = request_headers(request.headers());
    tracing::debug!(method = %method, path = target.split('?').next().unwrap_or("/"), "gateway request");
    let head = HttpRequestHead {
        method: method.as_str().to_owned(),
        target,
        headers,
    };
    if head.validate().is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            Some(("BAD_REQUEST", "Invalid request")),
        );
    }

    let stream = match mux.open_http(head).await {
        Ok(stream) => stream,
        Err(_) => return host_offline(),
    };

    let mut body = request.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                let _ = stream
                    .reset(ErrorCode::Cancelled, "local request body cancelled")
                    .await;
                return error_response(StatusCode::BAD_REQUEST, None);
            }
        };
        if send_chunks(&stream, chunk).await.is_err() {
            let _ = stream
                .reset(ErrorCode::Unavailable, "tunnel unavailable")
                .await;
            return host_offline();
        }
    }
    if stream.finish().await.is_err() {
        let _ = stream
            .reset(ErrorCode::Unavailable, "tunnel unavailable")
            .await;
        return host_offline();
    }

    let response_head = match tokio::time::timeout(RESPONSE_HEAD_TIMEOUT, stream.recv()).await {
        Err(_) => {
            let _ = stream
                .reset(ErrorCode::RequestTimeout, "response timeout")
                .await;
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                Some(("REQUEST_TIMEOUT", "Upstream response timed out")),
            );
        }
        Ok(Err(_)) => return host_offline(),
        Ok(Ok(Some(Inbound::HttpResponse(head)))) => head,
        Ok(Ok(Some(Inbound::Reset { code, .. }))) => return map_reset(code),
        Ok(Ok(Some(Inbound::End))) | Ok(Ok(None)) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                Some(("BACKEND_ERROR", "Upstream closed before response")),
            );
        }
        Ok(Ok(Some(Inbound::Data(_)))) => {
            let _ = stream
                .reset(ErrorCode::ProtocolError, "body before response head")
                .await;
            return error_response(
                StatusCode::BAD_GATEWAY,
                Some(("PROTOCOL_ERROR", "Invalid upstream response")),
            );
        }
        Ok(Ok(Some(Inbound::WsMessage { .. } | Inbound::WsClose { .. }))) => {
            let _ = stream
                .reset(ErrorCode::ProtocolError, "websocket frame on HTTP stream")
                .await;
            return error_response(
                StatusCode::BAD_GATEWAY,
                Some(("PROTOCOL_ERROR", "Invalid upstream response")),
            );
        }
    };

    tracing::debug!(status = response_head.status, "gateway response head");
    build_streaming_response(response_head, stream)
}

async fn gateway_websocket(state: GatewayState, request: Request) -> Response<Body> {
    let mux = state.mux.borrow().clone();
    let Some(mux) = mux.filter(|mux| !mux.is_closed()) else {
        return host_offline();
    };

    let (mut parts, _body) = request.into_parts();
    let target = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_owned();
    let subprotocols = match ws_subprotocols(&parts.headers) {
        Ok(subprotocols) => subprotocols,
        Err(()) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                Some(("BAD_REQUEST", "Invalid websocket subprotocol")),
            )
        }
    };
    let head = OpenWs {
        target,
        subprotocols: subprotocols.clone(),
        headers: Vec::new(),
    };
    if head.validate().is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            Some(("BAD_REQUEST", "Invalid websocket request")),
        );
    }

    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(upgrade) => upgrade,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                Some(("BAD_REQUEST", "Invalid websocket upgrade")),
            );
        }
    };

    let stream = match mux.open_ws(head).await {
        Ok(stream) => stream,
        Err(TransportError::FeatureUnsupported) => {
            return error_response(
                StatusCode::NOT_IMPLEMENTED,
                Some(("UNAVAILABLE", "WebSocket forwarding is not negotiated")),
            )
        }
        Err(_) => return host_offline(),
    };

    let upgrade = upgrade
        .max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE);
    let upgrade = if subprotocols.is_empty() {
        upgrade
    } else {
        upgrade.protocols(subprotocols)
    };
    upgrade.on_upgrade(move |socket| bridge_ws(socket, stream))
}

async fn bridge_ws(socket: WebSocket, stream: Stream) {
    let (mut sink, mut source) = socket.split();
    let stream = Arc::new(stream);

    loop {
        tokio::select! {
            downstream = source.next() => {
                match downstream {
                    Some(Ok(Message::Text(text))) => {
                        if stream
                            .send_ws_message(
                                WsOpcode::Text,
                                Bytes::copy_from_slice(text.as_bytes()),
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if stream
                            .send_ws_message(WsOpcode::Binary, bytes)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let (code, reason) = frame
                            .as_ref()
                            .map(|frame| (Some(frame.code), frame.reason.to_string()))
                            .unwrap_or((None, String::new()));
                        let _ = stream.send_ws_close(code, &reason).await;
                        let _ = sink.send(Message::Close(frame)).await;
                        let _ = sink.close().await;
                        break;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Err(_)) | None => {
                        let _ = stream
                            .reset(ErrorCode::Cancelled, "local websocket closed")
                            .await;
                        break;
                    }
                }
            }
            inbound = stream.recv() => {
                match inbound {
                    Ok(Some(Inbound::WsMessage {
                        opcode: WsOpcode::Text,
                        payload,
                    })) => {
                        let Ok(text) = String::from_utf8(payload.to_vec()) else {
                            let _ = stream
                                .reset(ErrorCode::ProtocolError, "invalid websocket text")
                                .await;
                            break;
                        };
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Inbound::WsMessage {
                        opcode: WsOpcode::Binary,
                        payload,
                    })) => {
                        if sink.send(Message::Binary(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Inbound::WsMessage {
                        opcode: WsOpcode::Continuation,
                        ..
                    })) => {
                        let _ = stream
                            .reset(
                                ErrorCode::ProtocolError,
                                "unexpected websocket continuation",
                            )
                            .await;
                        break;
                    }
                    Ok(Some(Inbound::WsClose { code, reason })) => {
                        // Acknowledge the peer's close on the OCT stream. This
                        // completes the close handshake and lets both muxes
                        // reap the stream instead of retaining a half-closed
                        // entry.
                        let _ = stream.send_ws_close(code, &reason).await;
                        let frame = CloseFrame {
                            code: code.unwrap_or(1000),
                            reason: reason.into(),
                        };
                        let _ = sink.send(Message::Close(Some(frame))).await;
                        let _ = sink.close().await;
                        break;
                    }
                    Ok(Some(Inbound::Reset { .. })) | Ok(None) | Err(_) => break,
                    Ok(Some(
                        Inbound::HttpResponse(_) | Inbound::Data(_) | Inbound::End,
                    )) => {
                        let _ = stream
                            .reset(ErrorCode::ProtocolError, "unexpected HTTP frame on websocket")
                            .await;
                        break;
                    }
                }
            }
        }
    }
}

fn ws_subprotocols(headers: &HeaderMap) -> Result<Vec<String>, ()> {
    let mut protocols = Vec::new();
    for value in headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
        let value = value.to_str().map_err(|_| ())?;
        for protocol in value.split(',') {
            let protocol = protocol.trim();
            if protocol.is_empty() {
                continue;
            }
            validate_ws_subprotocol(protocol).map_err(|_| ())?;
            if protocols.iter().all(|existing| existing != protocol) {
                if protocols.len() >= MAX_SUBPROTOCOLS {
                    return Err(());
                }
                protocols.push(protocol.to_owned());
            }
        }
    }
    Ok(protocols)
}

async fn send_chunks(stream: &Stream, bytes: Bytes) -> Result<(), oct_transport::TransportError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + oct_protocol::MAX_FRAME_PAYLOAD).min(bytes.len());
        stream.send_data(bytes.slice(offset..end)).await?;
        offset = end;
    }
    Ok(())
}

fn build_streaming_response(
    head: oct_protocol::HttpResponseHead,
    stream: Stream,
) -> Response<Body> {
    let status = match StatusCode::from_u16(head.status) {
        Ok(status) => status,
        Err(_) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                Some(("BACKEND_ERROR", "Invalid upstream status")),
            )
        }
    };
    let body_stream = stream::unfold(stream, |stream| async move {
        match stream.recv().await {
            Ok(Some(Inbound::Data(bytes))) => Some((Ok::<Bytes, io::Error>(bytes), stream)),
            Ok(Some(Inbound::End)) | Ok(None) => None,
            Ok(Some(Inbound::Reset { .. })) | Err(_) => {
                Some((Err(io::Error::other("upstream stream reset")), stream))
            }
            Ok(Some(Inbound::HttpResponse(_))) => {
                Some((Err(io::Error::other("duplicate response head")), stream))
            }
            Ok(Some(Inbound::WsMessage { .. } | Inbound::WsClose { .. })) => Some((
                Err(io::Error::other("websocket frame on HTTP stream")),
                stream,
            )),
        }
    });
    let mut response = Response::new(Body::from_stream(body_stream));
    *response.status_mut() = status;
    for (name, value) in head.headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) else {
            continue;
        };
        response.headers_mut().append(name, value);
    }
    response
}

fn request_headers(source: &HeaderMap) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(source.len().min(64));
    for (name, value) in source {
        let name = name.as_str();
        if is_hop_by_hop(name)
            || matches!(
                name,
                "host" | "authorization" | "proxy-authorization" | "origin"
            )
            || name == "forwarded"
            || name.starts_with("x-forwarded-")
            || name == "x-real-ip"
        {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        headers.push((name.to_owned(), value.to_owned()));
    }
    headers
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
            | "expect"
    ) || name.starts_with("sec-websocket-")
}

fn has_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        || headers
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
}

fn map_reset(code: ErrorCode) -> Response<Body> {
    match code {
        ErrorCode::HostOffline | ErrorCode::Unavailable | ErrorCode::HostRevoked => host_offline(),
        ErrorCode::RequestTimeout => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            Some(("REQUEST_TIMEOUT", "Upstream request timed out")),
        ),
        ErrorCode::BackendError => error_response(
            StatusCode::BAD_GATEWAY,
            Some(("BACKEND_ERROR", "Upstream request failed")),
        ),
        ErrorCode::Unauthorized => error_response(
            StatusCode::UNAUTHORIZED,
            Some(("UNAUTHORIZED", "Upstream request unauthorized")),
        ),
        ErrorCode::OverLimit => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            Some(("OVER_LIMIT", "Upstream limit exceeded")),
        ),
        ErrorCode::Cancelled => error_response(StatusCode::BAD_GATEWAY, None),
        _ => error_response(
            StatusCode::BAD_GATEWAY,
            Some(("PROTOCOL_ERROR", "Tunnel request failed")),
        ),
    }
}

fn host_offline() -> Response<Body> {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        Some(("HOST_OFFLINE", "OpenCode host is offline")),
    )
}

fn error_response(
    status: StatusCode,
    oct_error: Option<(&'static str, &'static str)>,
) -> Response<Body> {
    let mut response = (status, "OpenCode tunnel request failed").into_response();
    if let Some((code, message)) = oct_error {
        response
            .headers_mut()
            .insert("x-oct-error", HeaderValue::from_static(code));
        *response.body_mut() = Body::from(message);
    }
    response
}
