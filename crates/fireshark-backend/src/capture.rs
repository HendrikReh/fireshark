use std::path::Path;
use std::time::Duration;

use crate::backend::{BackendCapabilities, BackendKind};

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend error: {0}")]
    Open(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone)]
pub struct BackendSummary {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub timestamp: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct BackendLayer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct BackendIssue {
    pub kind: String,
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct BackendPacket {
    pub index: usize,
    pub summary: BackendSummary,
    pub layers: Vec<BackendLayer>,
    pub issues: Vec<BackendIssue>,
}

pub struct BackendCapture {
    pub(crate) kind: BackendKind,
    pub(crate) capabilities: BackendCapabilities,
    pub(crate) packets: Vec<BackendPacket>,
    pub(crate) protocol_counts: Vec<(String, usize)>,
    pub(crate) endpoint_counts: Vec<(String, usize)>,
}

impl BackendCapture {
    /// Construct a `BackendCapture` from pre-built components.
    ///
    /// Used by backend implementations (native, tshark) to return results.
    pub fn new(
        kind: BackendKind,
        capabilities: BackendCapabilities,
        packets: Vec<BackendPacket>,
        protocol_counts: Vec<(String, usize)>,
        endpoint_counts: Vec<(String, usize)>,
    ) -> Self {
        Self {
            kind,
            capabilities,
            packets,
            protocol_counts,
            endpoint_counts,
        }
    }

    pub fn open(path: impl AsRef<Path>, kind: BackendKind) -> Result<Self, BackendError> {
        match kind {
            BackendKind::Native => crate::native::open(path),
            BackendKind::Tshark => crate::tshark::open(path),
        }
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.kind
    }

    pub fn capabilities(&self) -> &BackendCapabilities {
        &self.capabilities
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn packet(&self, index: usize) -> Option<&BackendPacket> {
        self.packets.get(index)
    }

    pub fn packets(&self) -> &[BackendPacket] {
        &self.packets
    }

    pub fn protocol_counts(&self) -> &[(String, usize)] {
        &self.protocol_counts
    }

    pub fn endpoint_counts(&self) -> &[(String, usize)] {
        &self.endpoint_counts
    }
}
