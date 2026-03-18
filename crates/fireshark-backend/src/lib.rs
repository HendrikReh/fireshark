//! Backend abstraction for fireshark capture analysis.
//!
//! Provides `BackendKind` selection (native or tshark) and a unified
//! `BackendCapture` type that both CLI and MCP can consume.

mod backend;
mod capture;
pub mod compare;
mod native;
pub mod reassembly;
mod tshark;

pub use backend::{BackendCapabilities, BackendKind};
pub use capture::{
    BackendCapture, BackendError, BackendIssue, BackendLayer, BackendPacket, BackendSummary,
};
pub use compare::{CaptureComparison, compare};
pub use reassembly::{
    Direction, FollowMode, HttpExchange, StreamPayload, StreamSegment, TlsCertInfo,
};
