//! MCP (Model Context Protocol) client infrastructure.
//!
//! Layering mirrors `infra::llm` / `infra::db`:
//!
//! ```text
//! McpPool ──owns──> McpClient ──over──> McpTransport (OagwTransport)
//!    │                                        │
//!    └── read-through tool cache              └── OAGW proxy_request
//! ```
//!
//! Only the `tools/*` subset of MCP is implemented and all traffic is routed
//! through OAGW over HTTP Streamable (no stdio) — see DESIGN.md §"MCP Servers
//! Support".

pub mod cache;
pub mod client;
pub mod error;
pub mod oagw_upstream;
pub mod pool;
pub mod transport;
pub mod types;

#[cfg(test)]
pub mod test_support;

pub use client::McpClient;
pub use error::{McpError, McpResult};
pub use oagw_upstream::{ParsedMcpUrl, ProvisionedUpstream};
pub use pool::{BreakerConfig, CachedTool, McpDispatcher, McpPool, McpServerConn};
pub use transport::{McpHttpRequest, McpHttpResponse, McpTransport, OagwTransport};
pub use types::{
    InitializeResult, ListServersResult, McpAuth, McpContent, McpToolDefinition, McpToolResult,
    McpTrustLevel, RegistryServer,
};
