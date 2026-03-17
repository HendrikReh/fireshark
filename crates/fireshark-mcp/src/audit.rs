use std::collections::{BTreeMap, BTreeSet};

use fireshark_core::Layer;

use crate::analysis::AnalyzedCapture;
use crate::model::{FindingEvidenceView, FindingView};

const ISSUE_RATIO_THRESHOLD: f64 = 0.5;
const UNKNOWN_RATIO_THRESHOLD: f64 = 0.5;
const SCAN_FAN_OUT_THRESHOLD: usize = 5;
const MAX_EVIDENCE_PACKETS: usize = 100;
const SUSPICIOUS_PORTS: [u16; 5] = [23, 445, 2323, 3389, 5900];

pub struct AuditEngine;

impl AuditEngine {
    pub fn audit(capture: &AnalyzedCapture) -> Vec<FindingView> {
        let mut findings = Vec::new();

        if let Some(finding) = audit_decode_issues(capture) {
            findings.push(finding);
        }

        if let Some(finding) = audit_unknown_traffic(capture) {
            findings.push(finding);
        }

        findings.extend(audit_scan_activity(capture));
        findings.extend(audit_suspicious_ports(capture));

        findings
    }
}

fn audit_decode_issues(capture: &AnalyzedCapture) -> Option<FindingView> {
    let packet_indexes = capture
        .packets()
        .iter()
        .enumerate()
        .filter_map(|(index, packet)| (!packet.packet().issues().is_empty()).then_some(index))
        .take(MAX_EVIDENCE_PACKETS)
        .collect::<Vec<_>>();

    finding_for_ratio(
        RatioFindingSpec {
            id: "decode-issues",
            category: "decode_issues",
            severity: "high",
            title: "Decode issues affect a large share of packets",
            summary: "Packets contain malformed or truncated decode results that may indicate capture corruption or evasive traffic.",
            threshold: ISSUE_RATIO_THRESHOLD,
        },
        capture.packet_count(),
        packet_indexes,
    )
}

fn audit_unknown_traffic(capture: &AnalyzedCapture) -> Option<FindingView> {
    let packet_indexes = capture
        .packets()
        .iter()
        .enumerate()
        .filter_map(|(index, packet)| {
            (packet.summary().protocol.eq_ignore_ascii_case("unknown")).then_some(index)
        })
        .take(MAX_EVIDENCE_PACKETS)
        .collect::<Vec<_>>();

    finding_for_ratio(
        RatioFindingSpec {
            id: "unknown-traffic",
            category: "unknown_traffic",
            severity: "medium",
            title: "Unknown traffic dominates the capture",
            summary: "A large portion of packets could not be classified beyond the link layer, which reduces audit confidence.",
            threshold: UNKNOWN_RATIO_THRESHOLD,
        },
        capture.packet_count(),
        packet_indexes,
    )
}

fn audit_scan_activity(capture: &AnalyzedCapture) -> Vec<FindingView> {
    let mut source_targets = BTreeMap::<String, BTreeMap<String, Vec<usize>>>::new();

    for (index, packet) in capture.packets().iter().enumerate() {
        let Some(source) = source_host(packet.packet().layers()) else {
            continue;
        };
        let Some(destination) = destination_host(packet.packet().layers()) else {
            continue;
        };

        let dest_indexes = source_targets
            .entry(source)
            .or_default()
            .entry(destination)
            .or_default();
        if dest_indexes.len() < MAX_EVIDENCE_PACKETS {
            dest_indexes.push(index);
        }
    }

    source_targets
        .into_iter()
        .filter_map(|(source, targets)| {
            if targets.len() < SCAN_FAN_OUT_THRESHOLD {
                return None;
            }

            let packet_indexes = scan_activity_evidence(&targets);

            Some(FindingView {
                id: format!("scan-activity-{source}"),
                severity: String::from("high"),
                category: String::from("scan_activity"),
                title: format!("Endpoint fan-out from {source} looks scan-like"),
                summary: format!(
                    "{source} contacted {} distinct destinations in a single capture.",
                    targets.len()
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes,
                    description: format!(
                        "Observed fan-out to {} unique destination hosts.",
                        targets.len()
                    ),
                }],
            })
        })
        .collect()
}

fn scan_activity_evidence(targets: &BTreeMap<String, Vec<usize>>) -> Vec<usize> {
    let mut packet_indexes = targets
        .values()
        .filter_map(|indexes| indexes.first().copied())
        .take(MAX_EVIDENCE_PACKETS)
        .collect::<Vec<_>>();

    if packet_indexes.len() == MAX_EVIDENCE_PACKETS {
        return packet_indexes;
    }

    packet_indexes.extend(
        targets
            .values()
            .flat_map(|indexes| indexes.iter().skip(1).copied())
            .take(MAX_EVIDENCE_PACKETS - packet_indexes.len()),
    );

    packet_indexes
}

fn audit_suspicious_ports(capture: &AnalyzedCapture) -> Vec<FindingView> {
    let suspicious_ports = BTreeSet::from(SUSPICIOUS_PORTS);
    let mut ports = BTreeMap::<u16, Vec<usize>>::new();

    for (index, packet) in capture.packets().iter().enumerate() {
        let Some((_, destination_port)) = packet.packet().transport_ports() else {
            continue;
        };

        if suspicious_ports.contains(&destination_port) {
            let indexes = ports.entry(destination_port).or_default();
            if indexes.len() < MAX_EVIDENCE_PACKETS {
                indexes.push(index);
            }
        }
    }

    ports
        .into_iter()
        .map(|(port, packet_indexes)| FindingView {
            id: format!("suspicious-port-{port}"),
            severity: String::from("medium"),
            category: String::from("suspicious_ports"),
            title: format!("Traffic observed on suspicious destination port {port}"),
            summary: format!(
                "The capture includes packets targeting destination port {port}, which commonly appears in audit findings."
            ),
            evidence: vec![FindingEvidenceView {
                packet_indexes,
                description: format!("Packets targeted destination port {port}."),
            }],
        })
        .collect()
}

struct RatioFindingSpec {
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    title: &'static str,
    summary: &'static str,
    threshold: f64,
}

fn finding_for_ratio(
    spec: RatioFindingSpec,
    packet_count: usize,
    packet_indexes: Vec<usize>,
) -> Option<FindingView> {
    if packet_count == 0 {
        return None;
    }

    let ratio = packet_indexes.len() as f64 / packet_count as f64;
    if ratio < spec.threshold {
        return None;
    }

    Some(FindingView {
        id: spec.id.to_string(),
        severity: spec.severity.to_string(),
        category: spec.category.to_string(),
        title: spec.title.to_string(),
        summary: spec.summary.to_string(),
        evidence: vec![FindingEvidenceView {
            packet_indexes,
            description: format!(
                "{} affected {:.0}% of packets in the capture.",
                spec.category,
                ratio * 100.0
            ),
        }],
    })
}

fn source_host(layers: &[Layer]) -> Option<String> {
    layers.iter().find_map(|layer| match layer {
        Layer::Ipv4(layer) => Some(layer.source.to_string()),
        Layer::Ipv6(layer) => Some(layer.source.to_string()),
        _ => None,
    })
}

fn destination_host(layers: &[Layer]) -> Option<String> {
    layers.iter().find_map(|layer| match layer {
        Layer::Ipv4(layer) => Some(layer.destination.to_string()),
        Layer::Ipv6(layer) => Some(layer.destination.to_string()),
        _ => None,
    })
}
