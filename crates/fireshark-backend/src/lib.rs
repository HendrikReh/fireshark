//! Backend abstraction for fireshark capture analysis.
//!
//! Provides `BackendKind` selection (native or tshark) and a unified
//! `BackendCapture` type that both CLI and MCP can consume.

mod backend;
mod capture;
mod native;

pub use backend::{BackendCapabilities, BackendKind};
pub use capture::{
    BackendCapture, BackendError, BackendIssue, BackendLayer, BackendPacket, BackendSummary,
};
