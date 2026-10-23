//! Outbound host agent and fixed-origin HTTP/SSE proxy for OpenCode V2.

mod agent;
mod upstream;

pub use agent::{HostAgent, HostConfig, HostError};
pub use upstream::BackendProxy;
