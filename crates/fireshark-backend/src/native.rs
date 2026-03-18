use std::path::Path;

use fireshark_core::{PacketSummary, TrackingPipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::backend::{BackendCapabilities, BackendKind};
use crate::capture::*;

pub fn open(path: impl AsRef<Path>) -> Result<BackendCapture, BackendError> {
    let reader = CaptureReader::open(path).map_err(|e| BackendError::Open(e.to_string()))?;
    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    let mut packets = Vec::new();

    for (index, result) in pipeline.by_ref().enumerate() {
        let decoded = match result {
            Ok(d) => d,
            Err(_) => continue,
        };

        let summary_data: PacketSummary = decoded.summary();
        let summary = BackendSummary {
            protocol: summary_data.protocol,
            source: summary_data.source,
            destination: summary_data.destination,
            length: summary_data.length,
            timestamp: summary_data.timestamp,
        };

        let layers = decoded
            .packet()
            .layers()
            .iter()
            .map(|l| BackendLayer {
                name: l.name().to_string(),
                fields: Vec::new(),
            })
            .collect();

        let issues = decoded
            .packet()
            .issues()
            .iter()
            .map(|i| BackendIssue {
                kind: format!("{:?}", i.kind()),
                offset: i.offset(),
            })
            .collect();

        packets.push(BackendPacket {
            index,
            summary,
            layers,
            issues,
        });
    }

    let (protocol_counts, endpoint_counts) = summarize_packets(&packets);
    let stream_count = pipeline.into_tracker().stream_count();

    Ok(BackendCapture {
        kind: BackendKind::Native,
        capabilities: BackendCapabilities {
            supports_streams: true,
            supports_decode_issues: true,
            supports_native_filter: true,
            supports_layer_spans: true,
            supports_audit: true,
            supports_reassembly: false,
        },
        packets,
        protocol_counts,
        endpoint_counts,
        stream_count,
        path: None,
    })
}
