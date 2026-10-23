use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::{stream, SinkExt, StreamExt};
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use oct_protocol::httpwire::{validate_response_headers, HttpResponseHead};
use oct_protocol::{ErrorCode, HttpRequestHead, OpenWs, WsOpcode, MAX_WS_MESSAGE};
use oct_transport::{Inbound, OpenHandler, Stream};
use reqwest::redirect::Policy;
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use url::Url;

use crate::HostError;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_POOL_IDLE_PER_HOST: usize = 0;

/// HTTP/SSE bridge to one validated, fixed loopback origin. Request and
/// response bodies are streamed; the upstream Basic password is applied only
/// here on the host and is never included in OCT metadata.
pub struct BackendProxy {
    client: reqwest::Client,
    upstream: Url,
    origin: String,
    backend_password: Option<String>,
}

impl BackendProxy {
    pub(crate) fn new(upstream: Url, backend_password: Option<String>) -> Result<Self, HostError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(Policy::none())
            .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
            .pool_max_idle_per_host(UPSTREAM_POOL_IDLE_PER_HOST)
            .build()
            .map_err(|_| HostError::HttpClient)?;
        let origin = upstream.origin().ascii_serialization();
        Ok(Self {
            client,
            upstream,
            origin,
            backend_password,
        })
    }

    async fn proxy_http(&self, stream: Stream, head: HttpRequestHead) {
        if head.validate().is_err() {
            let _ = stream
                .reset(ErrorCode::BadRequest, "invalid request head")
                .await;
            return;
        }

        let target = match self.target_url(&head.target) {
            Ok(target) => target,
            Err(()) => {
                let _ = stream
                    .reset(ErrorCode::BadRequest, "invalid request target")
                    .await;
                return;
            }
        };
        let method = match Method::from_bytes(head.method.as_bytes()) {
            Ok(method) => method,
            Err(_) => {
                let _ = stream.reset(ErrorCode::BadRequest, "invalid method").await;
                return;
            }
        };
        let headers = match request_headers(&head) {
            Ok(headers) => headers,
            Err(()) => {
                let _ = stream
                    .reset(ErrorCode::BadRequest, "invalid request headers")
                    .await;
                return;
            }
        };

        let bodyless = matches!(method, Method::GET | Method::HEAD);
        let body_reader = RequestBodyReader {
            stream: Arc::new(Mutex::new(stream)),
            done: Arc::new(AtomicBool::new(false)),
        };
        let body =
            reqwest::Body::wrap_stream(stream::unfold(body_reader.clone(), next_request_chunk));
        let mut request = self.client.request(method, target).headers(headers);
        if !bodyless {
            request = request.body(body);
        }
        if let Some(password) = &self.backend_password {
            request = request.basic_auth("opencode", Some(password));
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => {
                body_reader.done.store(true, Ordering::SeqCst);
                let stream = body_reader.stream.lock().await;
                let _ = stream
                    .reset(ErrorCode::BackendError, "upstream request failed")
                    .await;
                return;
            }
        };

        // Some backends return an early response before consuming the request
        // body. Drain the already-bounded incoming stream so it cannot fill the
        // mux queue while the response is being relayed.
        if !drain_request_body(&body_reader).await {
            return;
        }

        let status = response.status().as_u16();
        let response_headers = response_headers(response.headers());
        let response_head = HttpResponseHead {
            status,
            headers: response_headers,
        };
        if response_head.validate().is_err() {
            let stream = body_reader.stream.lock().await;
            let _ = stream
                .reset(ErrorCode::BackendError, "invalid upstream response")
                .await;
            return;
        }

        {
            let stream = body_reader.stream.lock().await;
            if stream.send_response(response_head).await.is_err() {
                return;
            }
        }

        tracing::debug!(status, "upstream response received");
        let mut chunks = response.bytes_stream();
        loop {
            let next = tokio::select! {
                chunk = chunks.next() => Some(chunk),
                _ = wait_for_cancel(&body_reader) => None,
            };
            let Some(chunk) = next else {
                // The local client dropped the response. Dropping `chunks`
                // cancels the upstream request/SSE subscription.
                return;
            };
            match chunk {
                Some(Ok(bytes)) => {
                    let stream = body_reader.stream.lock().await;
                    if send_body_chunks(&stream, bytes).await.is_err() {
                        return;
                    }
                }
                Some(Err(_)) => {
                    let stream = body_reader.stream.lock().await;
                    let _ = stream
                        .reset(ErrorCode::BackendError, "upstream response interrupted")
                        .await;
                    return;
                }
                None => break,
            }
        }
        let stream = body_reader.stream.lock().await;
        let _ = stream.finish().await;
    }

    fn target_url(&self, target: &str) -> Result<Url, ()> {
        let candidate = Url::parse(&format!("{}{}", self.origin, target)).map_err(|_| ())?;
        if candidate.origin() != self.upstream.origin() {
            return Err(());
        }

        // URL parsers normalize dot segments. Reject a target if that would
        // change its raw origin-form path or query instead of silently
        // rewriting what the caller sent.
        let (raw_path, raw_query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target, None),
        };
        if candidate.path() != raw_path || candidate.query() != raw_query {
            return Err(());
        }
        Ok(candidate)
    }

    fn ws_target_url(&self, target: &str) -> Result<Url, ()> {
        if target.starts_with("//") {
            return Err(());
        }
        let mut candidate = self.target_url(target)?;
        let scheme = if self.upstream.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        candidate.set_scheme(scheme).map_err(|_| ())?;
        if candidate.host_str() != self.upstream.host_str()
            || candidate.port_or_known_default() != self.upstream.port_or_known_default()
        {
            return Err(());
        }
        Ok(candidate)
    }

    async fn proxy_ws(&self, stream: Stream, head: OpenWs) {
        if head.validate().is_err() {
            let _ = stream
                .reset(ErrorCode::BadRequest, "invalid websocket request")
                .await;
            return;
        }
        let target = match self.ws_target_url(&head.target) {
            Ok(target) => target,
            Err(()) => {
                let _ = stream
                    .reset(ErrorCode::BadRequest, "invalid websocket target")
                    .await;
                return;
            }
        };

        let mut request = match target.as_str().into_client_request() {
            Ok(request) => request,
            Err(_) => {
                let _ = stream
                    .reset(ErrorCode::BadRequest, "invalid websocket request")
                    .await;
                return;
            }
        };

        // OpenCode tickets are single-use and Basic auth must not be mixed with
        // a ticket-bearing upgrade. Restrict ticket mode to the exact PTY
        // connect route so an arbitrary `?ticket=` cannot suppress Basic on a
        // different upstream WebSocket path.
        let ticket_mode = is_pty_connect_target(&head.target);
        if !ticket_mode {
            if let Some(password) = &self.backend_password {
                let credentials = format!("opencode:{password}");
                let value = format!("Basic {}", STANDARD.encode(credentials.as_bytes()));
                let Ok(value) = HeaderValue::from_str(&value) else {
                    let _ = stream
                        .reset(ErrorCode::BackendError, "invalid backend credentials")
                        .await;
                    return;
                };
                request.headers_mut().insert(AUTHORIZATION, value);
            }
        }
        if !head.subprotocols.is_empty() {
            let Ok(value) = HeaderValue::from_str(&head.subprotocols.join(", ")) else {
                let _ = stream
                    .reset(ErrorCode::BadRequest, "invalid websocket subprotocol")
                    .await;
                return;
            };
            request
                .headers_mut()
                .insert(http::header::SEC_WEBSOCKET_PROTOCOL, value);
        }

        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_WS_MESSAGE);
        config.max_frame_size = Some(MAX_WS_MESSAGE);
        let connected = tokio::time::timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            connect_async_with_config(request, Some(config), true),
        )
        .await;

        let upstream = match connected {
            Err(_) => {
                let _ = stream
                    .reset(ErrorCode::RequestTimeout, "upstream websocket timed out")
                    .await;
                return;
            }
            Ok(Err(error)) => {
                let (code, reason) = match error {
                    WsError::Http(response) if response.status().as_u16() == 401 => {
                        (ErrorCode::Unauthorized, "upstream websocket unauthorized")
                    }
                    WsError::Http(response) if response.status().as_u16() == 403 => {
                        (ErrorCode::Denied, "upstream websocket denied")
                    }
                    _ => (ErrorCode::BackendError, "upstream websocket failed"),
                };
                let _ = stream.reset(code, reason).await;
                return;
            }
            Ok(Ok((upstream, _response))) => upstream,
        };

        let stream = Arc::new(stream);
        let (mut upstream_sink, mut upstream_source) = upstream.split();

        loop {
            tokio::select! {
                upstream_message = upstream_source.next() => {
                    match upstream_message {
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
                                .map(|frame| {
                                    (Some(u16::from(frame.code)), frame.reason.to_string())
                                })
                                .unwrap_or((None, String::new()));
                            let _ = stream.send_ws_close(code, &reason).await;
                            let _ = upstream_sink.close().await;
                            break;
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        Some(Ok(Message::Frame(_))) => {}
                        Some(Err(_)) | None => {
                            let _ = stream
                                .reset(ErrorCode::BackendError, "upstream websocket closed")
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
                            let Ok(text) = std::str::from_utf8(&payload) else {
                                let _ = stream
                                    .reset(ErrorCode::BadRequest, "invalid websocket text")
                                    .await;
                                break;
                            };
                            if upstream_sink
                                .send(Message::Text(text.to_owned().into()))
                                .await
                                .is_err()
                            {
                                let _ = stream
                                    .reset(ErrorCode::BackendError, "upstream websocket closed")
                                    .await;
                                break;
                            }
                        }
                        Ok(Some(Inbound::WsMessage {
                            opcode: WsOpcode::Binary,
                            payload,
                        })) => {
                            if upstream_sink.send(Message::Binary(payload)).await.is_err() {
                                let _ = stream
                                    .reset(ErrorCode::BackendError, "upstream websocket closed")
                                    .await;
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
                            // Acknowledge the close on the OCT stream so both
                            // muxes can remove the terminal stream.
                            let _ = stream.send_ws_close(code, &reason).await;
                            let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: code.unwrap_or(1000).into(),
                                reason: reason.into(),
                            };
                            let _ = upstream_sink.send(Message::Close(Some(frame))).await;
                            let _ = upstream_sink.close().await;
                            break;
                        }
                        Ok(Some(Inbound::Reset { .. })) | Ok(None) | Err(_) => break,
                        Ok(Some(Inbound::HttpResponse(_) | Inbound::Data(_) | Inbound::End)) => {
                            let _ = stream
                                .reset(
                                    ErrorCode::ProtocolError,
                                    "unexpected HTTP frame on websocket",
                                )
                                .await;
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn send_body_chunks(
    stream: &Stream,
    bytes: Bytes,
) -> Result<(), oct_transport::TransportError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + oct_protocol::MAX_FRAME_PAYLOAD).min(bytes.len());
        stream.send_data(bytes.slice(offset..end)).await?;
        offset = end;
    }
    Ok(())
}

#[async_trait]
impl OpenHandler for BackendProxy {
    async fn on_http(&self, stream: Stream, head: HttpRequestHead) {
        self.proxy_http(stream, head).await;
    }

    async fn on_ws(&self, stream: Stream, head: OpenWs) {
        self.proxy_ws(stream, head).await;
    }
}

#[derive(Clone)]
struct RequestBodyReader {
    stream: Arc<Mutex<Stream>>,
    done: Arc<AtomicBool>,
}

async fn next_request_chunk(
    reader: RequestBodyReader,
) -> Option<(Result<Bytes, io::Error>, RequestBodyReader)> {
    if reader.done.load(Ordering::SeqCst) {
        return None;
    }
    let message = reader.stream.lock().await.recv().await;
    match message {
        Ok(Some(Inbound::Data(bytes))) => Some((Ok(bytes), reader)),
        Ok(Some(Inbound::End)) | Ok(None) => {
            reader.done.store(true, Ordering::SeqCst);
            None
        }
        Ok(Some(Inbound::Reset { .. }))
        | Ok(Some(Inbound::HttpResponse(_)))
        | Ok(Some(Inbound::WsMessage { .. }))
        | Ok(Some(Inbound::WsClose { .. }))
        | Err(_) => {
            reader.done.store(true, Ordering::SeqCst);
            Some((Err(io::Error::other("request stream cancelled")), reader))
        }
    }
}

async fn wait_for_cancel(reader: &RequestBodyReader) {
    reader.stream.lock().await.wait_reset().await;
}

async fn drain_request_body(reader: &RequestBodyReader) -> bool {
    if reader.done.load(Ordering::SeqCst) {
        return true;
    }
    loop {
        let message = reader.stream.lock().await.recv().await;
        match message {
            Ok(Some(Inbound::Data(_))) => {}
            Ok(Some(Inbound::End)) | Ok(None) => {
                reader.done.store(true, Ordering::SeqCst);
                return true;
            }
            Ok(Some(Inbound::Reset { .. }))
            | Ok(Some(Inbound::HttpResponse(_)))
            | Ok(Some(Inbound::WsMessage { .. }))
            | Ok(Some(Inbound::WsClose { .. }))
            | Err(_) => {
                reader.done.store(true, Ordering::SeqCst);
                return false;
            }
        }
    }
}

fn is_pty_connect_target(target: &str) -> bool {
    let Some((path, _query)) = target.split_once('?') else {
        return false;
    };
    if !has_ticket_query(target) {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/pty/") else {
        return false;
    };
    let Some(id) = rest.strip_suffix("/connect") else {
        return false;
    };
    !id.is_empty()
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn has_ticket_query(target: &str) -> bool {
    let Some((_, query)) = target.split_once('?') else {
        return false;
    };
    url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "ticket")
}

fn request_headers(head: &HttpRequestHead) -> Result<HeaderMap, ()> {
    let mut headers = HeaderMap::new();
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "forwarded"
            || lower == "accept-encoding"
            || lower == "x-real-ip"
            || lower.starts_with("x-forwarded-")
        {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        let value = HeaderValue::from_str(value).map_err(|_| ())?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn response_headers(source: &HeaderMap) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(source.len().min(64));
    for (name, value) in source {
        let name = name.as_str();
        if matches!(
            name,
            "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "upgrade"
        ) {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        headers.push((name.to_owned(), value.to_owned()));
    }
    if validate_response_headers(&headers).is_ok() {
        headers
    } else {
        // Drop all optional headers if any backend value fails the protocol's
        // strict ASCII/size policy. Do not forward a partially ambiguous set.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> BackendProxy {
        BackendProxy::new(
            Url::parse("http://127.0.0.1:4096").unwrap(),
            Some("secret".into()),
        )
        .unwrap()
    }

    #[test]
    fn ticket_detection_is_query_name_based() {
        assert!(has_ticket_query("/api/pty/x/connect?ticket=abc"));
        assert!(has_ticket_query("/api/pty/x/connect?ticket"));
        assert!(has_ticket_query("/x?noticket=1&ticket=abc"));
        assert!(!has_ticket_query("/x?noticket=1"));
        assert!(!has_ticket_query("/x"));
    }

    #[test]
    fn ticket_mode_is_restricted_to_the_pty_connect_route() {
        assert!(is_pty_connect_target("/api/pty/pty_1/connect?ticket=abc"));
        assert!(!is_pty_connect_target("/api/pty/pty_1?ticket=abc"));
        assert!(!is_pty_connect_target("/api/session?ticket=abc"));
        assert!(!is_pty_connect_target("/api/pty/../connect?ticket=abc"));
        assert!(!is_pty_connect_target("/api/pty/a/b/connect?ticket=abc"));
        assert!(!is_pty_connect_target("/api/pty/pty_1/connect"));
    }

    #[test]
    fn websocket_targets_stay_on_the_fixed_origin() {
        let proxy = proxy();
        let target = proxy
            .ws_target_url("/api/pty/pty_1/connect?ticket=abc")
            .unwrap();
        assert_eq!(target.scheme(), "ws");
        assert_eq!(target.host_str(), Some("127.0.0.1"));
        assert_eq!(target.port(), Some(4096));
        assert_eq!(target.path(), "/api/pty/pty_1/connect");
        assert_eq!(target.query(), Some("ticket=abc"));

        assert!(proxy
            .ws_target_url("/api/pty/pty_1/connect?ticket=1#fragment")
            .is_err());
        assert!(proxy.ws_target_url("/../escape").is_err());
        assert!(proxy.ws_target_url("//attacker.example/x").is_err());
        assert!(proxy.ws_target_url("http://attacker.example/pty").is_err());
    }
}
