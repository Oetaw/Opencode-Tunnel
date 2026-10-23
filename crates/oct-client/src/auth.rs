use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) struct AuthState {
    expected_hash: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct AuthMiddlewareState {
    pub auth: std::sync::Arc<AuthState>,
    pub port: u16,
}

impl AuthState {
    pub(crate) fn new(password: &str) -> Self {
        let mut credentials = b"opencode:".to_vec();
        credentials.extend_from_slice(password.as_bytes());
        let expected_hash = Sha256::digest(credentials).into();
        Self { expected_hash }
    }

    fn authenticates(&self, request: &Request) -> bool {
        let Some(value) = request.headers().get(AUTHORIZATION) else {
            return false;
        };
        if value.as_bytes().len() > 1024 {
            return false;
        }
        let Ok(value) = value.to_str() else {
            return false;
        };
        if !value
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Basic "))
        {
            return false;
        }
        let Some(payload) = value.get(6..) else {
            return false;
        };
        let Ok(credentials) = STANDARD.decode(payload) else {
            return false;
        };
        let actual_hash: [u8; 32] = Sha256::digest(credentials).into();
        bool::from(self.expected_hash.ct_eq(&actual_hash))
    }
}

pub(crate) async fn authenticate(
    axum::extract::State(state): axum::extract::State<AuthMiddlewareState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !allowed_host(request.headers().get(HOST), state.port)
        || !allowed_origin(request.headers().get(ORIGIN), state.port)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !state.auth.authenticates(&request) {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"OpenCode\""),
        );
        return response;
    }
    next.run(request).await
}

fn allowed_host(value: Option<&HeaderValue>, port: u16) -> bool {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let ipv4 = format!("127.0.0.1:{port}");
    let localhost = format!("localhost:{port}");
    value.eq_ignore_ascii_case(&ipv4) || value.eq_ignore_ascii_case(&localhost)
}

fn allowed_origin(value: Option<&HeaderValue>, port: u16) -> bool {
    let Some(value) = value else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Ok(origin) = url::Url::parse(value) else {
        return false;
    };
    origin.scheme() == "http"
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin.path() == "/"
        && origin.port_or_known_default() == Some(port)
        && matches!(origin.host_str(), Some("127.0.0.1" | "localhost"))
}
