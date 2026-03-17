use std::collections::{BTreeMap, BTreeSet, HashSet};

use fireshark_core::Layer;

use crate::analysis::AnalyzedCapture;
use crate::model::{FindingEvidenceView, FindingView};

const ISSUE_RATIO_THRESHOLD: f64 = 0.5;
const UNKNOWN_RATIO_THRESHOLD: f64 = 0.5;
const SCAN_FAN_OUT_THRESHOLD: usize = 5;
const MAX_EVIDENCE_PACKETS: usize = 100;
const SUSPICIOUS_PORTS: [u16; 5] = [23, 445, 2323, 3389, 5900];

const CLEARTEXT_PORTS: [(u16, &str); 5] = [
    (21, "FTP"),
    (23, "Telnet"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
];

const DNS_TUNNEL_LONG_LABEL_LEN: usize = 50;
const DNS_TUNNEL_UNIQUE_NAMES_THRESHOLD: usize = 50;
const DNS_TUNNEL_TXT_QUERY_THRESHOLD: usize = 10;

const RST_STORM_THRESHOLD: u16 = 3;
const HALF_OPEN_PACKET_THRESHOLD: usize = 10;
const SYN_FLAG: u8 = 0x02;
const ACK_FLAG: u8 = 0x10;
const FIN_FLAG: u8 = 0x01;
const RST_FLAG: u8 = 0x04;
const SYN_ACK_FLAGS: u8 = SYN_FLAG | ACK_FLAG;

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
        findings.extend(audit_cleartext_credentials(capture));
        findings.extend(audit_dns_tunneling(capture));
        findings.extend(audit_connection_anomalies(capture));

        findings
    }
}

fn audit_decode_issues(capture: &AnalyzedCapture) -> Option<FindingView> {
    let all_affected = capture
        .packets()
        .iter()
        .enumerate()
        .filter_map(|(index, packet)| (!packet.packet().issues().is_empty()).then_some(index));

    let affected_count = all_affected.clone().count();

    let packet_indexes = all_affected.take(MAX_EVIDENCE_PACKETS).collect::<Vec<_>>();

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
        affected_count,
        packet_indexes,
    )
}

fn audit_unknown_traffic(capture: &AnalyzedCapture) -> Option<FindingView> {
    let all_affected = capture
        .packets()
        .iter()
        .enumerate()
        .filter_map(|(index, packet)| {
            (packet.summary().protocol.eq_ignore_ascii_case("unknown")).then_some(index)
        });

    let affected_count = all_affected.clone().count();

    let packet_indexes = all_affected.take(MAX_EVIDENCE_PACKETS).collect::<Vec<_>>();

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
        affected_count,
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

fn audit_cleartext_credentials(capture: &AnalyzedCapture) -> Vec<FindingView> {
    let cleartext_ports = BTreeMap::from(CLEARTEXT_PORTS);
    let mut ports = BTreeMap::<u16, Vec<usize>>::new();

    for (index, packet) in capture.packets().iter().enumerate() {
        let Some((_, destination_port)) = packet.packet().transport_ports() else {
            continue;
        };

        if cleartext_ports.contains_key(&destination_port) {
            let indexes = ports.entry(destination_port).or_default();
            if indexes.len() < MAX_EVIDENCE_PACKETS {
                indexes.push(index);
            }
        }
    }

    ports
        .into_iter()
        .map(|(port, packet_indexes)| {
            let name = cleartext_ports[&port];
            let lower_name = name.to_lowercase();
            FindingView {
                id: format!("cleartext-{lower_name}"),
                severity: String::from("high"),
                category: String::from("cleartext_credentials"),
                title: format!("{name} traffic on port {port} may expose credentials in cleartext"),
                summary: format!(
                    "{name} transmits data without encryption. Credentials, session tokens, \
                     and other sensitive information sent over port {port} can be intercepted \
                     by anyone with network access."
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes,
                    description: format!("Packets targeted {name} destination port {port}."),
                }],
            }
        })
        .collect()
}

fn audit_dns_tunneling(capture: &AnalyzedCapture) -> Vec<FindingView> {
    struct SourceStats {
        unique_names: HashSet<String>,
        long_label_count: usize,
        txt_query_count: usize,
        packet_indexes: Vec<usize>,
    }

    let mut sources: BTreeMap<String, SourceStats> = BTreeMap::new();

    for (index, packet) in capture.packets().iter().enumerate() {
        let has_dns = packet
            .packet()
            .layers()
            .iter()
            .any(|l| matches!(l, Layer::Dns(_)));
        if !has_dns {
            continue;
        }

        let Some(source) = source_host(packet.packet().layers()) else {
            continue;
        };

        let stats = sources.entry(source).or_insert_with(|| SourceStats {
            unique_names: HashSet::new(),
            long_label_count: 0,
            txt_query_count: 0,
            packet_indexes: Vec::new(),
        });

        if stats.packet_indexes.len() < MAX_EVIDENCE_PACKETS {
            stats.packet_indexes.push(index);
        }

        for layer in packet.packet().layers() {
            if let Layer::Dns(dns) = layer {
                if let Some(ref name) = dns.query_name {
                    stats.unique_names.insert(name.clone());
                    if name
                        .split('.')
                        .any(|segment| segment.len() > DNS_TUNNEL_LONG_LABEL_LEN)
                    {
                        stats.long_label_count += 1;
                    }
                }
                if dns.query_type == Some(16) {
                    stats.txt_query_count += 1;
                }
            }
        }
    }

    sources
        .into_iter()
        .filter_map(|(source, stats)| {
            let mut indicators = Vec::new();

            if stats.unique_names.len() > DNS_TUNNEL_UNIQUE_NAMES_THRESHOLD {
                indicators.push(format!(
                    "{} unique query names (threshold: {})",
                    stats.unique_names.len(),
                    DNS_TUNNEL_UNIQUE_NAMES_THRESHOLD
                ));
            }
            if stats.long_label_count > 0 {
                indicators.push(format!(
                    "{} queries with labels longer than {} characters",
                    stats.long_label_count, DNS_TUNNEL_LONG_LABEL_LEN
                ));
            }
            if stats.txt_query_count > DNS_TUNNEL_TXT_QUERY_THRESHOLD {
                indicators.push(format!(
                    "{} TXT queries (threshold: {})",
                    stats.txt_query_count, DNS_TUNNEL_TXT_QUERY_THRESHOLD
                ));
            }

            if indicators.is_empty() {
                return None;
            }

            Some(FindingView {
                id: format!("dns-tunneling-{source}"),
                severity: String::from("high"),
                category: String::from("dns_tunneling"),
                title: format!("Possible DNS tunneling activity from {source}"),
                summary: format!(
                    "DNS traffic from {source} exhibits indicators of tunneling: {}.",
                    indicators.join("; ")
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes: stats.packet_indexes,
                    description: format!("DNS queries from {source} with tunneling indicators."),
                }],
            })
        })
        .collect()
}

fn audit_connection_anomalies(capture: &AnalyzedCapture) -> Vec<FindingView> {
    let mut findings = Vec::new();

    for meta in capture.streams() {
        // Only inspect TCP streams (protocol 6).
        if meta.key.protocol != 6 {
            continue;
        }

        let id = meta.id;
        let endpoint_a = format!("{}:{}", meta.key.addr_lo, meta.key.port_lo);
        let endpoint_b = format!("{}:{}", meta.key.addr_hi, meta.key.port_hi);

        // Incomplete handshake: SYN seen but never a SYN+ACK in the same packet.
        if meta.tcp_flags_seen & SYN_FLAG != 0
            && meta.tcp_flags_seen & SYN_ACK_FLAGS != SYN_ACK_FLAGS
        {
            let packet_indexes = stream_evidence_indexes(capture, id);
            findings.push(FindingView {
                id: format!("incomplete-handshake-{id}"),
                severity: String::from("medium"),
                category: String::from("connection_anomaly"),
                title: format!(
                    "Incomplete TCP handshake on stream {id} ({endpoint_a} \u{2194} {endpoint_b})"
                ),
                summary: format!(
                    "Stream {id} contains a SYN but no SYN+ACK was observed, \
                     indicating an incomplete TCP handshake."
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes,
                    description: format!("Packets from stream {id} with incomplete handshake."),
                }],
            });
        }

        // RST storm: many RST packets on the same stream.
        if meta.rst_count >= RST_STORM_THRESHOLD {
            let packet_indexes = stream_evidence_indexes(capture, id);
            findings.push(FindingView {
                id: format!("rst-storm-{id}"),
                severity: String::from("medium"),
                category: String::from("connection_anomaly"),
                title: format!("RST storm on stream {id} ({} RST packets)", meta.rst_count),
                summary: format!(
                    "Stream {id} contains {} RST packets, which may indicate \
                     a connection teardown storm or port scanning.",
                    meta.rst_count
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes,
                    description: format!("Packets from stream {id} exhibiting RST storm behavior."),
                }],
            });
        }

        // Half-open: handshake completed (SYN+ACK seen) but no FIN or RST,
        // with a significant number of packets.
        if meta.tcp_flags_seen & SYN_ACK_FLAGS == SYN_ACK_FLAGS
            && meta.tcp_flags_seen & FIN_FLAG == 0
            && meta.tcp_flags_seen & RST_FLAG == 0
            && meta.packet_count >= HALF_OPEN_PACKET_THRESHOLD
        {
            let packet_indexes = stream_evidence_indexes(capture, id);
            findings.push(FindingView {
                id: format!("half-open-{id}"),
                severity: String::from("low"),
                category: String::from("connection_anomaly"),
                title: format!(
                    "Half-open connection on stream {id} ({} packets, no FIN/RST)",
                    meta.packet_count
                ),
                summary: format!(
                    "Stream {id} exchanged {} packets after the handshake \
                     but was never closed with FIN or RST.",
                    meta.packet_count
                ),
                evidence: vec![FindingEvidenceView {
                    packet_indexes,
                    description: format!("Packets from stream {id} with no connection teardown."),
                }],
            });
        }
    }

    findings
}

fn stream_evidence_indexes(capture: &AnalyzedCapture, stream_id: u32) -> Vec<usize> {
    capture
        .packets()
        .iter()
        .enumerate()
        .filter(|(_, pkt)| pkt.stream_id() == Some(stream_id))
        .map(|(i, _)| i)
        .take(MAX_EVIDENCE_PACKETS)
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
    affected_count: usize,
    packet_indexes: Vec<usize>,
) -> Option<FindingView> {
    if packet_count == 0 {
        return None;
    }

    let ratio = affected_count as f64 / packet_count as f64;
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
