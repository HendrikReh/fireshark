//! Backend abstraction for fireshark capture analysis.
//!
//! Provides `BackendKind` selection (native or tshark) and a unified
//! `BackendCapture` type that both CLI and MCP can consume. Also hosts
//! the domain-level `AnalyzedCapture` and `AuditEngine` so that both
//! CLI and MCP can share analysis logic without the CLI depending on
//! MCP internals.

pub mod analysis;
pub mod audit;
mod backend;
mod capture;
pub mod compare;
mod native;
pub mod reassembly;
mod tshark;

pub use analysis::{AnalysisError, AnalyzedCapture, DEFAULT_MAX_PACKETS};
pub use audit::{AuditEngine, Finding, FindingEvidence, VALID_PROFILES};
pub use backend::{BackendCapabilities, BackendKind};
pub use capture::{
    BackendCapture, BackendError, BackendIssue, BackendLayer, BackendPacket, BackendSummary,
};
pub use compare::{CaptureComparison, compare};
pub use reassembly::{
    Direction, FollowMode, HttpExchange, StreamPayload, StreamSegment, TlsCertInfo,
};
