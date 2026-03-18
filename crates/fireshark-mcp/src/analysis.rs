use std::collections::BTreeMap;
use std::path::Path;

use fireshark_core::{DecodedFrame, PipelineError, StreamTracker, TrackingPipeline};
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
    tracker: StreamTracker,
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
        let mut pipeline = TrackingPipeline::new(reader, decode_packet);
        for result in &mut pipeline {
            let frame = match result {
                Ok(f) => f,
                Err(PipelineError::Decode(_)) => continue,
                Err(PipelineError::Frame(e)) => return Err(AnalysisError::Capture(e)),
            };
            packets.push(frame);
            if packets.len() >= max_packets {
                return Err(AnalysisError::TooLarge { max_packets });
            }
        }
        let tracker = pipeline.into_tracker();

        Ok(Self::from_packets_with_tracker(packets, tracker))
    }

    pub fn from_packets(packets: Vec<DecodedFrame>) -> Self {
        Self::from_packets_with_tracker(packets, StreamTracker::default())
    }

    pub fn from_packets_with_tracker(packets: Vec<DecodedFrame>, tracker: StreamTracker) -> Self {
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
            tracker,
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

    /// All stream metadata in ID order.
    pub fn streams(&self) -> &[fireshark_core::StreamMetadata] {
        self.tracker.streams()
    }

    /// The underlying stream tracker.
    pub fn tracker(&self) -> &StreamTracker {
        &self.tracker
    }

    /// Return all packets belonging to a given stream, with their indices.
    pub fn stream_packets(&self, stream_id: u32) -> Vec<(usize, &DecodedFrame)> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, pkt)| pkt.stream_id() == Some(stream_id))
            .collect()
    }
}
