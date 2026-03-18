use std::collections::BTreeMap;
use std::path::Path;

use crate::backend::{BackendCapabilities, BackendKind};
use crate::capture::*;

/// Open a capture file using the tshark backend.
///
/// Discovers tshark, runs it with `-T fields` output, and converts the
/// parsed packets into a `BackendCapture`.
pub fn open(path: impl AsRef<Path>) -> Result<BackendCapture, BackendError> {
    let capture = fireshark_tshark::open(path).map_err(|e| BackendError::Open(e.to_string()))?;

    let mut protocol_map: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoint_map: BTreeMap<String, usize> = BTreeMap::new();

    let packets: Vec<BackendPacket> = capture
        .packets
        .into_iter()
        .map(|pkt| {
            if !pkt.protocol.is_empty() {
                *protocol_map.entry(pkt.protocol.clone()).or_default() += 1;
            }
            if !pkt.source.is_empty() {
                *endpoint_map.entry(pkt.source.clone()).or_default() += 1;
            }
            if !pkt.destination.is_empty() {
                *endpoint_map.entry(pkt.destination.clone()).or_default() += 1;
            }

            let mut layers = Vec::new();
            if !pkt.protocol.is_empty() {
                layers.push(BackendLayer {
                    name: pkt.protocol.clone(),
                    fields: vec![("info".to_string(), pkt.info)],
                });
            }

            BackendPacket {
                index: pkt.frame_number,
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

    let mut protocol_counts: Vec<_> = protocol_map.into_iter().collect();
    protocol_counts.sort_by(|a, b| b.1.cmp(&a.1));
    let mut endpoint_counts: Vec<_> = endpoint_map.into_iter().collect();
    endpoint_counts.sort_by(|a, b| b.1.cmp(&a.1));

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
    ))
}
