use std::collections::BTreeMap;
use std::path::Path;

use fireshark_core::{DecodedFrame, Pipeline, PipelineError};
use fireshark_dissectors::{DecodeError, decode_packet};
use fireshark_file::{CaptureError, CaptureReader};
use thiserror::Error;

pub const DEFAULT_MAX_PACKETS: usize = 100_000;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error(transparent)]
    Capture(#[from] CaptureError),

    #[error(transparent)]
    Decode(#[from] DecodePipelineError),

    #[error("capture exceeds maximum packet count ({max_packets})")]
    TooLarge { max_packets: usize },
}

type DecodePipelineError = PipelineError<CaptureError, DecodeError>;

#[derive(Debug, Clone)]
pub struct AnalyzedCapture {
    packets: Vec<DecodedFrame>,
    protocol_counts: BTreeMap<String, usize>,
    endpoint_counts: BTreeMap<String, usize>,
}

impl AnalyzedCapture {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AnalysisError> {
        Self::open_with_limit(path, DEFAULT_MAX_PACKETS)
    }

    pub fn open_with_limit(
        path: impl AsRef<Path>,
        max_packets: usize,
    ) -> Result<Self, AnalysisError> {
        let reader = CaptureReader::open(path)?;
        let mut packets = Vec::new();
        for result in Pipeline::new(reader, decode_packet) {
            let frame = result.map_err(AnalysisError::from)?;
            packets.push(frame);
            if packets.len() > max_packets {
                return Err(AnalysisError::TooLarge { max_packets });
            }
        }

        Ok(Self::from_packets(packets))
    }

    pub fn from_packets(packets: Vec<DecodedFrame>) -> Self {
        let mut protocol_counts = BTreeMap::new();
        let mut endpoint_counts = BTreeMap::new();

        for packet in &packets {
            let summary = packet.summary();
            *protocol_counts.entry(summary.protocol).or_insert(0) += 1;

            for endpoint in [summary.source, summary.destination] {
                if endpoint.is_empty() {
                    continue;
                }

                *endpoint_counts.entry(endpoint).or_insert(0) += 1;
            }
        }

        Self {
            packets,
            protocol_counts,
            endpoint_counts,
        }
    }

    pub fn packets(&self) -> &[DecodedFrame] {
        &self.packets
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn protocol_counts(&self) -> &BTreeMap<String, usize> {
        &self.protocol_counts
    }

    pub fn endpoint_counts(&self) -> &BTreeMap<String, usize> {
        &self.endpoint_counts
    }
}
