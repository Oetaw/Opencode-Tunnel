//! Deterministic OpenCode-like backend and harness helpers for OCT tests.
//!
//! [`spawn_fake_backend`] starts an Axum server bound to `127.0.0.1:0` and
//! returns a [`FakeBackend`] whose `base_url` points at the ephemeral port. The
//! server is stopped when the last [`FakeBackend`] clone is dropped, or
//! immediately through [`FakeBackend::shutdown`].
//!
//! # Endpoints
//!
//! | Route | Behaviour |
//! |---|---|
//! | `GET /api/info` | Stable JSON with `version` `2.0.22`, `protocol` `2`, and capabilities. |
//! | `GET /api/event` | `text/event-stream` fed by [`BackendState::broadcast_event`]. |
//! | `POST /echo` | JSON echo of method, path/query, non-sensitive headers, and body. |
//! | `GET /status/{code}` | Responds with the requested status and a small JSON body. |
//! | `GET /large?bytes=N` | Deterministic bytes, capped by [`FakeBackendConfig::max_large_bytes`]. |
//! | `GET /delayed?ms=N` | Waits (capped by [`FakeBackendConfig::max_delay`]) then returns JSON. |
//! | `POST /upload` | Counts body bytes and returns a SHA-256 digest. |
//! | `GET /ws/echo` | WebSocket echo for text and binary messages. |
//!
//! Every non-streaming response is recorded in [`BackendState::requests`] with
//! its method, path, status, request-body bytes, and response-body bytes.
//! Authorization, cookie, and API-key headers are never echoed or recorded.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() {
//! let backend = oct_testkit::spawn_fake_backend().await;
//! assert!(backend.base_url.starts_with("http://127.0.0.1:"));
//!
//! let event = oct_testkit::SseEvent::json(&serde_json::json!({
//!     "type": "server.connected",
//!     "properties": {},
//! }));
//! backend.broadcast_event(event);
//! backend.shutdown();
//! # }
//! ```
//!
//! The body returned by `GET /large` and by `/upload` is deterministic:
//! byte `i` is `(i % 251) as u8`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine as _;
use bytes::BytesMut;
use futures_util::stream::{self, Stream};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Version string returned by `GET /api/info`.
pub const FAKE_OPENCODE_VERSION: &str = "2.0.22";

/// Protocol version returned by `GET /api/info`.
pub const FAKE_PROTOCOL_VERSION: u32 = 2;

/// Default SSE keepalive interval (15 seconds).
pub const DEFAULT_SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// Hard cap for `/large` responses and request bodies (8 MiB).
pub const MAX_FAKE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Hard cap for `/delayed`.
pub const MAX_FAKE_DELAY: Duration = Duration::from_secs(30);

/// Maximum accepted SSE keepalive interval.
const MAX_KEEPALIVE_MILLIS: u64 = 3_600_000;

const INFO_JSON: &str = concat!(
    r#"{"version":""#,
    "2.0.22",
    r#"","protocol":2,"capabilities":{"#,
    r#""events":true,"files":true,"http":true,"permissions":true,"#,
    r#""sessions":true,"streaming":true,"websocket":true}}"#
);

/// Configuration for a [`FakeBackend`].
#[derive(Debug, Clone)]
pub struct FakeBackendConfig {
    /// Interval between SSE keepalive comments.
    ///
    /// Defaults to [`DEFAULT_SSE_KEEPALIVE`]. Values are clamped to
    /// `1ms..=1h` so tests can shorten the interval without busy-looping.
    pub keepalive: Duration,

    /// Capacity of the SSE broadcast channel.
    ///
    /// Slow subscribers that fall more than this many events behind receive a
    /// `lagged` SSE comment instead of replay. Defaults to `128`.
    pub event_buffer: usize,

    /// Maximum number of request records retained in memory.
    ///
    /// Oldest records are evicted first. Defaults to `4096`.
    pub max_records: usize,

    /// Maximum request body bytes accepted by `/echo` and `/upload`.
    ///
    /// Clamped to `1..=8 MiB`. Defaults to 8 MiB.
    pub max_body_bytes: usize,

    /// Maximum delay honored by `/delayed`.
    ///
    /// Clamped to at most [`MAX_FAKE_DELAY`]. Defaults to 30 seconds.
    pub max_delay: Duration,

    /// Maximum response size produced by `/large`.
    ///
    /// Clamped to `1..=8 MiB`. Defaults to 8 MiB.
    pub max_large_bytes: usize,
}

impl Default for FakeBackendConfig {
    fn default() -> Self {
        Self {
            keepalive: DEFAULT_SSE_KEEPALIVE,
            event_buffer: 128,
            max_records: 4096,
            max_body_bytes: MAX_FAKE_BODY_BYTES,
            max_delay: MAX_FAKE_DELAY,
            max_large_bytes: MAX_FAKE_BODY_BYTES,
        }
    }
}

impl FakeBackendConfig {
    fn normalized(self) -> Self {
        Self {
            keepalive: Duration::from_millis(keepalive_millis(self.keepalive)),
            event_buffer: self.event_buffer.max(1),
            max_records: self.max_records.max(1),
            max_body_bytes: self.max_body_bytes.clamp(1, MAX_FAKE_BODY_BYTES),
            max_delay: self.max_delay.min(MAX_FAKE_DELAY),
            max_large_bytes: self.max_large_bytes.clamp(1, MAX_FAKE_BODY_BYTES),
        }
    }
}

/// One complete request/response pair observed by the fake backend.
///
/// Streaming responses (`/api/event`) and WebSocket upgrades record `0` for
/// `response_bytes`; the status still reflects the response that was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordedRequest {
    /// HTTP method, for example `GET` or `POST`.
    pub method: String,

    /// Request path without the query string.
    pub path: String,

    /// Response status code.
    pub status: u16,

    /// Request body bytes received.
    pub request_bytes: u64,

    /// Response body bytes produced.
    pub response_bytes: u64,
}

/// A server-sent event broadcast to connected `/api/event` subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    id: Option<String>,
    event: Option<String>,
    data: String,
    retry_ms: Option<u64>,
}

impl SseEvent {
    /// Creates an unnamed event with `data` as its payload.
    ///
    /// Newlines are supported; the SSE encoder splits them into multiple
    /// `data:` fields.
    pub fn data(data: impl Into<String>) -> Self {
        Self {
            id: None,
            event: None,
            data: data.into(),
            retry_ms: None,
        }
    }

    /// Creates an unnamed event whose payload is compact JSON for `value`.
    pub fn json(value: &Value) -> Self {
        Self::data(value.to_string())
    }

    /// Creates a named event. Line breaks in `event` are replaced with spaces.
    pub fn named(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            id: None,
            event: Some(sanitize_sse_field(event)),
            data: data.into(),
            retry_ms: None,
        }
    }

    /// Sets the SSE event id. Line breaks in `id` are replaced with spaces.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(sanitize_sse_field(id));
        self
    }

    /// Sets the SSE reconnect delay advertised with this event.
    pub fn with_retry(mut self, retry: Duration) -> Self {
        self.retry_ms = Some(u64::try_from(retry.as_millis()).unwrap_or(u64::MAX));
        self
    }

    /// Returns the event id, if set.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Returns the event name, if set.
    pub fn event(&self) -> Option<&str> {
        self.event.as_deref()
    }

    /// Returns the event payload.
    pub fn payload(&self) -> &str {
        &self.data
    }

    /// Returns the reconnect delay in milliseconds, if set.
    pub fn retry_ms(&self) -> Option<u64> {
        self.retry_ms
    }
}

/// Shared state for a running fake backend: event fan-out, request recording,
/// and runtime knobs such as the SSE keepalive interval.
pub struct BackendState {
    events: broadcast::Sender<SseEvent>,
    keepalive_ms: AtomicU64,
    total_subscribers: AtomicU64,
    peak_subscribers: AtomicUsize,
    records: Mutex<VecDeque<RecordedRequest>>,
    max_records: usize,
    max_body_bytes: usize,
    max_delay: Duration,
    max_large_bytes: usize,
}

impl BackendState {
    fn new(config: FakeBackendConfig) -> Self {
        let (events, _receiver) = broadcast::channel(config.event_buffer);
        Self {
            events,
            keepalive_ms: AtomicU64::new(keepalive_millis(config.keepalive)),
            total_subscribers: AtomicU64::new(0),
            peak_subscribers: AtomicUsize::new(0),
            records: Mutex::new(VecDeque::with_capacity(config.max_records.min(1024))),
            max_records: config.max_records,
            max_body_bytes: config.max_body_bytes,
            max_delay: config.max_delay,
            max_large_bytes: config.max_large_bytes,
        }
    }

    /// Returns the number of `/api/event` subscribers currently connected.
    pub fn subscriber_count(&self) -> usize {
        self.events.receiver_count()
    }

    /// Returns the total number of SSE subscriptions accepted since startup.
    pub fn total_subscribers(&self) -> u64 {
        self.total_subscribers.load(Ordering::Relaxed)
    }

    /// Returns the highest concurrent SSE subscriber count observed.
    pub fn peak_subscribers(&self) -> usize {
        self.peak_subscribers.load(Ordering::Relaxed)
    }

    /// Broadcasts `event` to all live subscribers.
    ///
    /// Returns the number of subscribers that received the event. Events sent
    /// while no subscriber is connected are dropped; this mirrors a live-only
    /// feed and never replays old events.
    pub fn broadcast_event(&self, event: SseEvent) -> usize {
        self.events.send(event).unwrap_or(0)
    }

    /// Broadcasts `value` as compact JSON in an unnamed SSE event.
    pub fn broadcast_json(&self, value: &Value) -> usize {
        self.broadcast_event(SseEvent::json(value))
    }

    /// Updates the keepalive interval for new and existing subscriptions.
    ///
    /// Values are clamped to `1ms..=1h`.
    pub fn set_keepalive(&self, keepalive: Duration) {
        self.keepalive_ms
            .store(keepalive_millis(keepalive), Ordering::Relaxed);
    }

    /// Returns the current keepalive interval.
    pub fn keepalive(&self) -> Duration {
        Duration::from_millis(self.keepalive_ms.load(Ordering::Relaxed))
    }

    /// Returns the configured maximum request body size.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Returns the configured maximum `/delayed` delay.
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Returns the configured maximum `/large` response size.
    pub fn max_large_bytes(&self) -> usize {
        self.max_large_bytes
    }

    /// Returns a snapshot of recorded requests, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.lock_records().iter().cloned().collect()
    }

    /// Returns the number of retained request records.
    pub fn request_count(&self) -> usize {
        self.lock_records().len()
    }

    /// Returns the most recent request record, if any.
    pub fn last_request(&self) -> Option<RecordedRequest> {
        self.lock_records().back().cloned()
    }

    /// Returns records whose path equals `path` (query string excluded).
    pub fn requests_for(&self, path: &str) -> Vec<RecordedRequest> {
        self.lock_records()
            .iter()
            .filter(|record| record.path == path)
            .cloned()
            .collect()
    }

    /// Removes all retained request records.
    pub fn clear_requests(&self) {
        self.lock_records().clear();
    }

    /// Waits until at least `count` SSE subscribers are connected.
    ///
    /// Returns `false` if `timeout` elapses first.
    pub async fn wait_for_subscribers(&self, count: usize, timeout: Duration) -> bool {
        wait_until(|| self.subscriber_count() >= count, timeout).await
    }

    /// Waits until no SSE subscribers remain.
    ///
    /// Returns `false` if `timeout` elapses first.
    pub async fn wait_for_no_subscribers(&self, timeout: Duration) -> bool {
        wait_until(|| self.subscriber_count() == 0, timeout).await
    }

    /// Waits until at least `count` requests have been recorded.
    ///
    /// Returns `false` if `timeout` elapses first.
    pub async fn wait_for_requests(&self, count: usize, timeout: Duration) -> bool {
        wait_until(|| self.request_count() >= count, timeout).await
    }

    fn subscribe(&self) -> broadcast::Receiver<SseEvent> {
        let receiver = self.events.subscribe();
        self.total_subscribers.fetch_add(1, Ordering::Relaxed);
        let current = self.subscriber_count();
        self.peak_subscribers.fetch_max(current, Ordering::Relaxed);
        receiver
    }

    fn record(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        request_bytes: u64,
        response_bytes: u64,
    ) {
        let record = RecordedRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            status: status.as_u16(),
            request_bytes,
            response_bytes,
        };

        let mut records = self.lock_records();
        if records.len() >= self.max_records {
            records.pop_front();
        }
        records.push_back(record);
    }

    fn lock_records(&self) -> MutexGuard<'_, VecDeque<RecordedRequest>> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A running fake OpenCode backend.
///
/// Cloning is cheap and shares both the server and its [`BackendState`]. The
/// server stops when the last clone is dropped.
#[derive(Clone)]
pub struct FakeBackend {
    /// Base URL, for example `http://127.0.0.1:34567`.
    pub base_url: String,

    /// Shared control and recording state.
    pub state: Arc<BackendState>,

    guard: Arc<ServerGuard>,
}

impl FakeBackend {
    /// Joins `path` onto [`Self::base_url`].
    pub fn url(&self, path: &str) -> String {
        join_url(&self.base_url, path)
    }

    /// Returns a `ws://` URL for `path` under the same host and port.
    pub fn ws_url(&self, path: &str) -> String {
        let base = self
            .base_url
            .strip_prefix("http://")
            .map_or_else(|| self.base_url.clone(), |rest| format!("ws://{rest}"));
        join_url(&base, path)
    }

    /// Returns a snapshot of recorded requests, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests()
    }

    /// Returns the most recent request record, if any.
    pub fn last_request(&self) -> Option<RecordedRequest> {
        self.state.last_request()
    }

    /// Broadcasts an SSE event to live `/api/event` subscribers.
    pub fn broadcast_event(&self, event: SseEvent) -> usize {
        self.state.broadcast_event(event)
    }

    /// Broadcasts a JSON value as an unnamed SSE event.
    pub fn broadcast_json(&self, value: &Value) -> usize {
        self.state.broadcast_json(value)
    }

    /// Returns the number of `/api/event` subscribers currently connected.
    pub fn subscriber_count(&self) -> usize {
        self.state.subscriber_count()
    }

    /// Waits until at least `count` SSE subscribers are connected.
    pub async fn wait_for_subscribers(&self, count: usize, timeout: Duration) -> bool {
        self.state.wait_for_subscribers(count, timeout).await
    }

    /// Stops the HTTP server and aborts open connections.
    pub fn shutdown(&self) {
        self.guard.stop();
    }
}

struct ServerGuard {
    token: CancellationToken,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl ServerGuard {
    fn stop(&self) {
        self.token.cancel();
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            handle.abort();
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Error returned when a fake backend listener cannot be created.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Binding or inspecting the loopback listener failed.
    #[error("failed to bind fake backend listener: {0}")]
    Bind(#[from] io::Error),
}

/// Spawns a fake backend with default settings.
///
/// # Panics
///
/// Panics only if the operating system refuses to bind `127.0.0.1:0`. Use
/// [`spawn_fake_backend_with`] to handle that failure.
pub async fn spawn_fake_backend() -> FakeBackend {
    match spawn_fake_backend_with(FakeBackendConfig::default()).await {
        Ok(backend) => backend,
        Err(error) => panic!("oct-testkit could not spawn a fake backend: {error}"),
    }
}

/// Spawns a fake backend with explicit settings.
///
/// The server is bound to `127.0.0.1:0`; the selected port is exposed through
/// [`FakeBackend::base_url`]. A background Tokio task serves it until the
/// returned handle is dropped or [`FakeBackend::shutdown`] is called.
pub async fn spawn_fake_backend_with(
    config: FakeBackendConfig,
) -> Result<FakeBackend, BackendError> {
    let state = Arc::new(BackendState::new(config.normalized()));
    let app = build_router(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let token = CancellationToken::new();
    let shutdown = token.clone();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await;
    });

    Ok(FakeBackend {
        base_url: format!("http://{addr}"),
        state,
        guard: Arc::new(ServerGuard {
            token,
            handle: Mutex::new(Some(handle)),
        }),
    })
}

fn build_router(state: Arc<BackendState>) -> Router {
    Router::new()
        .route("/api/info", get(api_info))
        .route("/api/event", get(api_event))
        .route("/echo", post(echo))
        .route("/status/{code}", get(status_code))
        .route("/large", get(large))
        .route("/delayed", get(delayed))
        .route("/upload", post(upload))
        .route("/ws/echo", get(ws_echo))
        .with_state(state)
}

async fn api_info(
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let body = Bytes::from_static(INFO_JSON.as_bytes());
    state.record("GET", uri.path(), StatusCode::OK, 0, body.len() as u64);
    json_response(StatusCode::OK, body)
}

async fn api_event(
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let receiver = state.subscribe();
    state.record("GET", uri.path(), StatusCode::OK, 0, 0);

    let stream = sse_stream(receiver, Arc::clone(&state));
    let mut response = Sse::new(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    response
}

async fn echo(
    State(state): State<Arc<BackendState>>,
    method: Method,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Response {
    let body = match read_body_bounded(body, state.max_body_bytes()).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge { received }) => {
            return json_response_recorded(
                &state,
                method.as_str(),
                uri.path(),
                StatusCode::PAYLOAD_TOO_LARGE,
                received,
                json!({
                    "error": "payload_too_large",
                    "limit": state.max_body_bytes(),
                }),
            );
        }
        Err(BodyReadError::Read) => {
            return json_response_recorded(
                &state,
                method.as_str(),
                uri.path(),
                StatusCode::BAD_REQUEST,
                0,
                json!({ "error": "body_read_error" }),
            );
        }
    };

    let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let mut selected = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in &headers {
        if is_sensitive_header(name.as_str()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            selected
                .entry(name.as_str().to_owned())
                .or_default()
                .push(value.to_owned());
        }
    }

    let mut selected_json = Map::new();
    for (name, values) in selected {
        let values = values.into_iter().map(Value::String).collect();
        selected_json.insert(name, Value::Array(values));
    }

    let body_text = std::str::from_utf8(&body).ok();
    let body_base64 = if body_text.is_some() {
        Value::Null
    } else {
        Value::String(base64::engine::general_purpose::STANDARD.encode(body.as_ref()))
    };

    let mut response = Map::new();
    response.insert(
        "method".to_owned(),
        Value::String(method.as_str().to_owned()),
    );
    response.insert("path".to_owned(), Value::String(uri.path().to_owned()));
    response.insert(
        "query".to_owned(),
        uri.query()
            .map_or(Value::Null, |query| Value::String(query.to_owned())),
    );
    response.insert(
        "target".to_owned(),
        Value::String(uri.query().map_or_else(
            || uri.path().to_owned(),
            |query| format!("{}?{query}", uri.path()),
        )),
    );
    response.insert("headers".to_owned(), Value::Object(selected_json));
    response.insert(
        "body".to_owned(),
        body_text.map_or(Value::Null, |text| Value::String(text.to_owned())),
    );
    response.insert("body_base64".to_owned(), body_base64);
    response.insert(
        "body_encoding".to_owned(),
        Value::String(
            if body_text.is_some() {
                "utf8"
            } else {
                "base64"
            }
            .to_owned(),
        ),
    );
    response.insert("body_len".to_owned(), json!(body_len));
    response.insert(
        "body_sha256".to_owned(),
        Value::String(hex::encode(Sha256::digest(body.as_ref()))),
    );

    json_response_recorded(
        &state,
        method.as_str(),
        uri.path(),
        StatusCode::OK,
        body_len,
        Value::Object(response),
    )
}

async fn status_code(
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
    Path(code): Path<String>,
) -> Response {
    let parsed = code
        .parse::<u16>()
        .ok()
        .and_then(|code| StatusCode::from_u16(code).ok())
        .filter(|status| status.as_u16() >= 200);

    let Some(status) = parsed else {
        return json_response_recorded(
            &state,
            "GET",
            uri.path(),
            StatusCode::BAD_REQUEST,
            0,
            json!({ "error": "invalid_status", "code": code }),
        );
    };

    if matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
    ) {
        state.record("GET", uri.path(), status, 0, 0);
        return status.into_response();
    }

    json_response_recorded(
        &state,
        "GET",
        uri.path(),
        status,
        0,
        json!({ "status": status.as_u16(), "ok": status.is_success() }),
    )
}

async fn large(State(state): State<Arc<BackendState>>, OriginalUri(uri): OriginalUri) -> Response {
    let requested = match query_u64(uri.query(), "bytes", 1024) {
        Ok(requested) => requested,
        Err(InvalidQuery) => return invalid_query_response(&state, "GET", uri.path(), "bytes"),
    };

    let len = requested.min(state.max_large_bytes() as u64);
    let len_usize = usize::try_from(len).unwrap_or(state.max_large_bytes());
    let body = deterministic_bytes(len_usize);

    state.record("GET", uri.path(), StatusCode::OK, 0, len);
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-oct-bytes"), value);
    }
    response
}

async fn delayed(
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let requested = match query_u64(uri.query(), "ms", 0) {
        Ok(requested) => requested,
        Err(InvalidQuery) => return invalid_query_response(&state, "GET", uri.path(), "ms"),
    };

    let max_delay_ms = u64::try_from(state.max_delay().as_millis()).unwrap_or(u64::MAX);
    let delay_ms = requested.min(max_delay_ms);
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    json_response_recorded(
        &state,
        "GET",
        uri.path(),
        StatusCode::OK,
        0,
        json!({
            "ok": true,
            "requested_ms": requested,
            "delayed_ms": delay_ms,
            "capped": delay_ms < requested,
        }),
    )
}

async fn upload(
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> Response {
    let body = match read_body_bounded(body, state.max_body_bytes()).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge { received }) => {
            return json_response_recorded(
                &state,
                "POST",
                uri.path(),
                StatusCode::PAYLOAD_TOO_LARGE,
                received,
                json!({
                    "error": "payload_too_large",
                    "limit": state.max_body_bytes(),
                }),
            );
        }
        Err(BodyReadError::Read) => {
            return json_response_recorded(
                &state,
                "POST",
                uri.path(),
                StatusCode::BAD_REQUEST,
                0,
                json!({ "error": "body_read_error" }),
            );
        }
    };

    let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let sha256 = hex::encode(Sha256::digest(body.as_ref()));
    json_response_recorded(
        &state,
        "POST",
        uri.path(),
        StatusCode::OK,
        bytes,
        json!({ "bytes": bytes, "sha256": sha256, "ok": true }),
    )
}

async fn ws_echo(
    ws: WebSocketUpgrade,
    State(state): State<Arc<BackendState>>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    state.record("GET", uri.path(), StatusCode::SWITCHING_PROTOCOLS, 0, 0);
    ws.on_upgrade(echo_socket)
}

async fn echo_socket(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        let reply = match message {
            Message::Text(text) => Message::Text(text),
            Message::Binary(data) => Message::Binary(data),
            // Tungstenite answers pings automatically.
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };

        if socket.send(reply).await.is_err() {
            break;
        }
    }
}

struct SseStreamState {
    receiver: broadcast::Receiver<SseEvent>,
    backend: Arc<BackendState>,
    next_keepalive: Instant,
    greeted: bool,
}

impl SseStreamState {
    async fn next(mut self) -> Option<(Result<Event, Infallible>, Self)> {
        if !self.greeted {
            self.greeted = true;
            return Some((Ok(Event::default().comment("connected")), self));
        }

        tokio::select! {
            biased;
            received = self.receiver.recv() => {
                match received {
                    Ok(event) => {
                        self.next_keepalive = instant_after(self.backend.keepalive());
                        Some((Ok(render_event(event)), self))
                    }
                    Err(broadcast::error::RecvError::Lagged(dropped)) => {
                        Some((Ok(Event::default().comment(format!("lagged {dropped}"))), self))
                    }
                    Err(broadcast::error::RecvError::Closed) => None,
                }
            }
            () = tokio::time::sleep_until(self.next_keepalive) => {
                self.next_keepalive = instant_after(self.backend.keepalive());
                Some((Ok(Event::default().comment("keepalive")), self))
            }
        }
    }
}

fn sse_stream(
    receiver: broadcast::Receiver<SseEvent>,
    backend: Arc<BackendState>,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    let state = SseStreamState {
        receiver,
        next_keepalive: instant_after(backend.keepalive()),
        backend,
        greeted: false,
    };
    stream::unfold(state, SseStreamState::next)
}

fn render_event(event: SseEvent) -> Event {
    let SseEvent {
        id,
        event,
        data,
        retry_ms,
    } = event;

    let mut wire = Event::default();
    if let Some(id) = id {
        wire = wire.id(id);
    }
    if let Some(name) = event {
        wire = wire.event(name);
    }
    if let Some(retry_ms) = retry_ms {
        wire = wire.retry(Duration::from_millis(retry_ms));
    }
    wire.data(data)
}

enum BodyReadError {
    TooLarge { received: u64 },
    Read,
}

async fn read_body_bounded(body: Body, limit: usize) -> Result<Bytes, BodyReadError> {
    let mut stream = body.into_data_stream();
    let capacity = limit.min(16 * 1024);
    let mut buffer = BytesMut::with_capacity(capacity);
    let mut received: usize = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyReadError::Read)?;
        received = received
            .checked_add(chunk.len())
            .ok_or(BodyReadError::TooLarge { received: u64::MAX })?;
        if received > limit {
            return Err(BodyReadError::TooLarge {
                received: u64::try_from(received).unwrap_or(u64::MAX),
            });
        }
        buffer.extend_from_slice(&chunk);
    }

    Ok(buffer.freeze())
}

fn json_response(status: StatusCode, body: Bytes) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn json_response_recorded(
    state: &BackendState,
    method: &str,
    path: &str,
    status: StatusCode,
    request_bytes: u64,
    value: Value,
) -> Response {
    let body = Bytes::from(value.to_string().into_bytes());
    state.record(
        method,
        path,
        status,
        request_bytes,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
    );
    json_response(status, body)
}

fn invalid_query_response(
    state: &BackendState,
    method: &str,
    path: &str,
    parameter: &str,
) -> Response {
    json_response_recorded(
        state,
        method,
        path,
        StatusCode::BAD_REQUEST,
        0,
        json!({ "error": "invalid_query", "parameter": parameter }),
    )
}

struct InvalidQuery;

fn query_u64(query: Option<&str>, key: &str, default: u64) -> Result<u64, InvalidQuery> {
    let Some(query) = query else {
        return Ok(default);
    };

    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name == key {
            return value.parse::<u64>().map_err(|_| InvalidQuery);
        }
    }

    Ok(default)
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-forwarded-authorization"
            | "x-oct-token"
            | "x-opencode-password"
    )
}

fn sanitize_sse_field(value: impl Into<String>) -> String {
    value
        .into()
        .chars()
        .map(|character| match character {
            '\r' | '\n' => ' ',
            other => other,
        })
        .collect()
}

fn keepalive_millis(keepalive: Duration) -> u64 {
    let millis = keepalive
        .as_millis()
        .clamp(1, u128::from(MAX_KEEPALIVE_MILLIS));
    u64::try_from(millis).unwrap_or(MAX_KEEPALIVE_MILLIS)
}

fn instant_after(duration: Duration) -> Instant {
    Instant::now()
        .checked_add(duration)
        .unwrap_or_else(Instant::now)
}

async fn wait_until<F>(mut predicate: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = instant_after(timeout);
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Returns `len` deterministic bytes where byte `i` is `(i % 251) as u8`.
pub fn deterministic_bytes(len: usize) -> Bytes {
    let bytes: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
    Bytes::from(bytes)
}
