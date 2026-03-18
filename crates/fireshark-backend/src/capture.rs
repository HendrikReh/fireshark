use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::backend::{BackendCapabilities, BackendKind};
use crate::reassembly::{FollowMode, StreamPayload, TlsCertInfo};

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
    /// Zero-based frame index within the capture.
    pub index: usize,
    pub summary: BackendSummary,
    pub layers: Vec<BackendLayer>,
    pub issues: Vec<BackendIssue>,
}

pub(crate) type CountEntries = Vec<(String, usize)>;
pub(crate) type PacketSummaryCounts = (CountEntries, CountEntries);

pub struct BackendCapture {
    pub(crate) kind: BackendKind,
    pub(crate) capabilities: BackendCapabilities,
    pub(crate) packets: Vec<BackendPacket>,
    pub(crate) protocol_counts: Vec<(String, usize)>,
    pub(crate) endpoint_counts: Vec<(String, usize)>,
    pub(crate) stream_count: usize,
    pub(crate) path: Option<PathBuf>,
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
        stream_count: usize,
    ) -> Self {
        Self {
            kind,
            capabilities,
            packets,
            protocol_counts,
            endpoint_counts,
            stream_count,
            path: None,
        }
    }

    pub fn open(path: impl AsRef<Path>, kind: BackendKind) -> Result<Self, BackendError> {
        let capture_path = path.as_ref().to_path_buf();
        let mut capture = match kind {
            BackendKind::Native => crate::native::open(&path),
            BackendKind::Tshark => crate::tshark::open(&path),
        }?;
        capture.path = Some(capture_path);
        Ok(capture)
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

    pub fn stream_count(&self) -> usize {
        self.stream_count
    }

    /// The capture file path, if available.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Follow/reassemble a stream using the tshark backend.
    ///
    /// Returns an error if the capture path is unavailable or the backend
    /// does not support reassembly.
    pub fn follow_stream(
        &self,
        stream_id: u32,
        mode: FollowMode,
    ) -> Result<StreamPayload, BackendError> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| BackendError::Unsupported("no capture path available".into()))?;
        if !self.capabilities.supports_reassembly {
            return Err(BackendError::Unsupported(
                "reassembly requires tshark backend".into(),
            ));
        }
        let (tshark_path, _version) =
            fireshark_tshark::discover().map_err(|e| BackendError::Open(e.to_string()))?;
        fireshark_tshark::follow::follow_stream(&tshark_path, path, stream_id, mode)
            .map_err(|e| BackendError::Open(e.to_string()))
    }

    /// Extract TLS certificate information from the capture using tshark.
    ///
    /// Returns an error if the capture path is unavailable or the backend
    /// does not support reassembly.
    pub fn extract_certificates(&self) -> Result<Vec<TlsCertInfo>, BackendError> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| BackendError::Unsupported("no capture path available".into()))?;
        if !self.capabilities.supports_reassembly {
            return Err(BackendError::Unsupported(
                "certificate extraction requires tshark backend".into(),
            ));
        }
        let (tshark_path, _version) =
            fireshark_tshark::discover().map_err(|e| BackendError::Open(e.to_string()))?;
        fireshark_tshark::certs::extract_certificates(&tshark_path, path)
            .map_err(|e| BackendError::Open(e.to_string()))
    }
}

pub(crate) fn summarize_packets(packets: &[BackendPacket]) -> PacketSummaryCounts {
    let mut protocol_map: BTreeMap<&str, usize> = BTreeMap::new();
    let mut endpoint_map: BTreeMap<&str, usize> = BTreeMap::new();

    for packet in packets {
        let summary = &packet.summary;

        if !summary.protocol.is_empty() {
            *protocol_map.entry(summary.protocol.as_str()).or_default() += 1;
        }
        if !summary.source.is_empty() {
            *endpoint_map.entry(summary.source.as_str()).or_default() += 1;
        }
        if !summary.destination.is_empty() {
            *endpoint_map
                .entry(summary.destination.as_str())
                .or_default() += 1;
        }
    }

    let mut protocol_counts: Vec<_> = protocol_map
        .into_iter()
        .map(|(protocol, count)| (protocol.to_string(), count))
        .collect();
    protocol_counts.sort_by(|a, b| b.1.cmp(&a.1));

    let mut endpoint_counts: Vec<_> = endpoint_map
        .into_iter()
        .map(|(endpoint, count)| (endpoint.to_string(), count))
        .collect();
    endpoint_counts.sort_by(|a, b| b.1.cmp(&a.1));

    (protocol_counts, endpoint_counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(protocol: &str, source: &str, destination: &str) -> BackendPacket {
        BackendPacket {
            index: 0,
            summary: BackendSummary {
                protocol: protocol.to_string(),
                source: source.to_string(),
                destination: destination.to_string(),
                length: 64,
                timestamp: None,
            },
            layers: Vec::new(),
            issues: Vec::new(),
        }
    }

    #[test]
    fn summarize_packets_counts_repeated_protocols_and_endpoints() {
        let packets = vec![
            packet("HTTP", "10.0.0.1:12345", "10.0.0.2:80"),
            packet("HTTP", "10.0.0.1:12345", "10.0.0.2:80"),
            packet("DNS", "10.0.0.3:5353", "10.0.0.4:53"),
        ];

        let (protocol_counts, endpoint_counts) = summarize_packets(&packets);

        assert_eq!(
            protocol_counts,
            vec![("HTTP".to_string(), 2), ("DNS".to_string(), 1)]
        );
        assert_eq!(
            endpoint_counts,
            vec![
                ("10.0.0.1:12345".to_string(), 2),
                ("10.0.0.2:80".to_string(), 2),
                ("10.0.0.3:5353".to_string(), 1),
                ("10.0.0.4:53".to_string(), 1),
            ]
        );
    }
}
