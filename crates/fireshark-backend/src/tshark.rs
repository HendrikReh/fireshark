use std::path::Path;

use crate::backend::{BackendCapabilities, BackendKind};
use crate::capture::*;

/// Open a capture file using the tshark backend.
///
/// Discovers tshark, runs it with `-T fields` output, and converts the
/// parsed packets into a `BackendCapture`.
pub fn open(path: impl AsRef<Path>) -> Result<BackendCapture, BackendError> {
    let capture = fireshark_tshark::open(path).map_err(|e| BackendError::Open(e.to_string()))?;

    let packets: Vec<BackendPacket> = capture
        .packets
        .into_iter()
        .map(|pkt| {
            let mut layers = Vec::new();
            if !pkt.protocol.is_empty() {
                layers.push(BackendLayer {
                    name: pkt.protocol.clone(),
                    fields: vec![("info".to_string(), pkt.info)],
                });
            }

            BackendPacket {
                index: pkt.frame_number.saturating_sub(1),
                summary: BackendSummary {
                    protocol: pkt.protocol,
                    source: pkt.source,
                    destination: pkt.destination,
                    length: pkt.length,
                    timestamp: pkt.timestamp,
                },
                layers,
                issues: Vec::new(),
            }
        })
        .collect();

    let (protocol_counts, endpoint_counts) = summarize_packets(&packets);

    Ok(BackendCapture::new(
        BackendKind::Tshark,
        BackendCapabilities {
            supports_streams: false,
            supports_decode_issues: false,
            supports_native_filter: false,
            supports_layer_spans: false,
            supports_audit: false,
            supports_reassembly: true,
        },
        packets,
        protocol_counts,
        endpoint_counts,
        0,
    ))
}
