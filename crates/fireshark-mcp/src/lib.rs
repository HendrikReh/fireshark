pub mod filter;
pub mod model;
pub mod query;
pub mod server;
pub mod session;
pub mod tools;

// Re-export shared analysis and audit types from fireshark-backend.
// These types live in the backend crate so the CLI and MCP server can
// use the same implementation without the CLI depending on MCP internals.
pub use fireshark_backend::analysis::{self, AnalysisError, AnalyzedCapture, DEFAULT_MAX_PACKETS};
pub use fireshark_backend::audit::{self, AuditEngine, VALID_PROFILES};
