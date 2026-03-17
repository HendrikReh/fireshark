use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use fireshark_core::{
    DecodeIssue, DecodedFrame, DnsLayer, EthernetLayer, Frame, Ipv4Layer, Layer, Packet,
    StreamTracker, TcpFlags, TcpLayer, UdpLayer,
};
use fireshark_mcp::analysis::AnalyzedCapture;
use fireshark_mcp::audit::AuditEngine;

#[test]
fn audit_flags_decode_issue_heavy_capture() {
    let capture = AnalyzedCapture::from_packets(vec![
        unknown_packet(vec![DecodeIssue::truncated(14)]),
        unknown_packet(vec![DecodeIssue::truncated(18)]),
        unknown_packet(vec![DecodeIssue::malformed(14)]),
        unknown_packet(Vec::new()),
    ]);

    let findings = AuditEngine::audit(&capture);

    assert!(
        findings
            .iter()
            .any(|finding| finding.category == "decode_issues")
    );
}

#[test]
fn audit_flags_unknown_traffic_concentration() {
    let capture = AnalyzedCapture::from_packets(vec![
        unknown_packet(Vec::new()),
        unknown_packet(Vec::new()),
        unknown_packet(Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.2", 443, Vec::new()),
    ]);

    let findings = AuditEngine::audit(&capture);

    assert!(
        findings
            .iter()
            .any(|finding| finding.category == "unknown_traffic")
    );
}

#[test]
fn audit_flags_scan_like_fan_out() {
    let capture = AnalyzedCapture::from_packets(vec![
        tcp_packet("10.0.0.1", "10.0.0.2", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.3", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.4", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.5", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.6", 80, Vec::new()),
    ]);

    let findings = AuditEngine::audit(&capture);

    assert!(
        findings
            .iter()
            .any(|finding| finding.category == "scan_activity")
    );
}

#[test]
fn scan_activity_evidence_preserves_destination_diversity_when_capped() {
    let mut packets = (0..100)
        .map(|_| tcp_packet("10.0.0.1", "10.0.0.2", 80, Vec::new()))
        .collect::<Vec<_>>();
    packets.extend([
        tcp_packet("10.0.0.1", "10.0.0.3", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.4", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.5", 80, Vec::new()),
        tcp_packet("10.0.0.1", "10.0.0.6", 80, Vec::new()),
    ]);

    let capture = AnalyzedCapture::from_packets(packets);
    let findings = AuditEngine::audit(&capture);
    let scan_finding = findings
        .iter()
        .find(|finding| finding.category == "scan_activity")
        .expect("scan activity finding");

    let evidence_destinations = scan_finding.evidence[0]
        .packet_indexes
        .iter()
        .map(|index| destination_for_packet(&capture, *index))
        .collect::<BTreeSet<_>>();

    assert_eq!(evidence_destinations.len(), 5);
}

#[test]
fn audit_flags_suspicious_port_usage() {
    let capture =
        AnalyzedCapture::from_packets(vec![tcp_packet("10.0.0.1", "10.0.0.2", 23, Vec::new())]);

    let findings = AuditEngine::audit(&capture);

    assert!(
        findings
            .iter()
            .any(|finding| finding.category == "suspicious_ports")
    );
}

fn unknown_packet(issues: Vec<DecodeIssue>) -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(vec![ethernet_layer(), Layer::Unknown], issues),
    )
}

fn tcp_packet(
    source: &str,
    destination: &str,
    destination_port: u16,
    issues: Vec<DecodeIssue>,
) -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(
            vec![
                ethernet_layer(),
                Layer::Ipv4(Ipv4Layer {
                    source: source.parse::<Ipv4Addr>().unwrap(),
                    destination: destination.parse::<Ipv4Addr>().unwrap(),
                    protocol: 6,
                    ttl: 64,
                    identification: 0,
                    dscp: 0,
                    ecn: 0,
                    dont_fragment: true,
                    fragment_offset: 0,
                    more_fragments: false,
                    header_checksum: 0,
                }),
                Layer::Tcp(TcpLayer {
                    source_port: 50_000,
                    destination_port,
                    seq: 0,
                    ack: 0,
                    data_offset: 5,
                    flags: TcpFlags {
                        fin: false,
                        syn: true,
                        rst: false,
                        psh: false,
                        ack: false,
                        urg: false,
                        ece: false,
                        cwr: false,
                    },
                    window: 1024,
                }),
            ],
            issues,
        ),
    )
}

fn frame() -> Frame {
    Frame::builder()
        .captured_len(64)
        .protocol("UNKNOWN")
        .data(vec![0; 64])
        .build()
}

fn ethernet_layer() -> Layer {
    Layer::Ethernet(EthernetLayer {
        destination: [0, 1, 2, 3, 4, 5],
        source: [6, 7, 8, 9, 10, 11],
        ether_type: 0x0800,
    })
}

fn dns_query_packet(source: &str, query_name: &str, query_type: u16) -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(
            vec![
                ethernet_layer(),
                Layer::Ipv4(Ipv4Layer {
                    source: source.parse::<Ipv4Addr>().unwrap(),
                    destination: "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
                    protocol: 17,
                    ttl: 64,
                    identification: 0,
                    dscp: 0,
                    ecn: 0,
                    dont_fragment: true,
                    fragment_offset: 0,
                    more_fragments: false,
                    header_checksum: 0,
                }),
                Layer::Udp(UdpLayer {
                    source_port: 50_000,
                    destination_port: 53,
                    length: 40,
                }),
                Layer::Dns(DnsLayer {
                    transaction_id: 0x1234,
                    is_response: false,
                    opcode: 0,
                    question_count: 1,
                    answer_count: 0,
                    query_name: Some(query_name.to_string()),
                    query_type: Some(query_type),
                    answers: Vec::new(),
                }),
            ],
            Vec::new(),
        ),
    )
}

fn tcp_packet_with_flags(
    source: &str,
    destination: &str,
    source_port: u16,
    destination_port: u16,
    flags: TcpFlags,
) -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(
            vec![
                ethernet_layer(),
                Layer::Ipv4(Ipv4Layer {
                    source: source.parse::<Ipv4Addr>().unwrap(),
                    destination: destination.parse::<Ipv4Addr>().unwrap(),
                    protocol: 6,
                    ttl: 64,
                    identification: 0,
                    dscp: 0,
                    ecn: 0,
                    dont_fragment: true,
                    fragment_offset: 0,
                    more_fragments: false,
                    header_checksum: 0,
                }),
                Layer::Tcp(TcpLayer {
                    source_port,
                    destination_port,
                    seq: 0,
                    ack: 0,
                    data_offset: 5,
                    flags,
                    window: 1024,
                }),
            ],
            Vec::new(),
        ),
    )
}

fn default_flags() -> TcpFlags {
    TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    }
}

/// Build an `AnalyzedCapture` with a properly populated `StreamTracker`.
fn tracked_capture(packets: Vec<DecodedFrame>) -> AnalyzedCapture {
    let mut tracker = StreamTracker::new();
    let tracked_packets: Vec<DecodedFrame> = packets
        .into_iter()
        .map(|decoded| {
            let stream_id = tracker.assign(&decoded);
            decoded.with_stream_id(stream_id)
        })
        .collect();
    AnalyzedCapture::from_packets_with_tracker(tracked_packets, tracker)
}

fn destination_for_packet(capture: &AnalyzedCapture, index: usize) -> String {
    capture.packets()[index]
        .packet()
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer.destination.to_string()),
            _ => None,
        })
        .expect("IPv4 destination")
}

#[test]
fn audit_flags_cleartext_ftp() {
    let capture =
        AnalyzedCapture::from_packets(vec![tcp_packet("10.0.0.1", "10.0.0.2", 21, Vec::new())]);

    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "cleartext_credentials")
        .expect("cleartext_credentials finding");
    assert_eq!(finding.id, "cleartext-ftp");
    assert_eq!(finding.severity, "high");
    assert!(finding.title.contains("FTP"));
}

#[test]
fn audit_flags_cleartext_telnet() {
    let capture =
        AnalyzedCapture::from_packets(vec![tcp_packet("10.0.0.1", "10.0.0.2", 23, Vec::new())]);

    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "cleartext_credentials")
        .expect("cleartext_credentials finding");
    assert_eq!(finding.id, "cleartext-telnet");
    assert_eq!(finding.severity, "high");
    assert!(finding.title.contains("Telnet"));
}

#[test]
fn audit_flags_dns_tunneling_long_labels() {
    let long_label = "a".repeat(60);
    let query_name = format!("{long_label}.example.com");

    let capture = AnalyzedCapture::from_packets(vec![dns_query_packet(
        "10.0.0.1",
        &query_name,
        1, // A record
    )]);

    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "dns_tunneling")
        .expect("dns_tunneling finding");
    assert_eq!(finding.id, "dns-tunneling-10.0.0.1");
    assert_eq!(finding.severity, "high");
    assert!(finding.summary.contains("labels longer than"));
}

#[test]
fn audit_flags_dns_tunneling_high_unique_count() {
    let packets: Vec<DecodedFrame> = (0..60)
        .map(|i| dns_query_packet("10.0.0.1", &format!("host-{i}.example.com"), 1))
        .collect();

    let capture = AnalyzedCapture::from_packets(packets);
    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "dns_tunneling")
        .expect("dns_tunneling finding");
    assert_eq!(finding.id, "dns-tunneling-10.0.0.1");
    assert!(finding.summary.contains("unique query names"));
}

#[test]
fn audit_does_not_flag_normal_dns() {
    let capture = AnalyzedCapture::from_packets(vec![
        dns_query_packet("10.0.0.1", "www.example.com", 1),
        dns_query_packet("10.0.0.1", "mail.example.com", 1),
        dns_query_packet("10.0.0.1", "api.example.com", 1),
    ]);

    let findings = AuditEngine::audit(&capture);

    assert!(
        !findings.iter().any(|f| f.category == "dns_tunneling"),
        "Normal DNS queries should not trigger dns_tunneling"
    );
}

#[test]
fn audit_flags_incomplete_handshake() {
    // SYN only, no SYN+ACK — incomplete handshake.
    let packets = vec![
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                syn: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                syn: true,
                ..default_flags()
            },
        ),
    ];

    let capture = tracked_capture(packets);
    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "connection_anomaly" && f.id.starts_with("incomplete-handshake"))
        .expect("incomplete handshake finding");
    assert_eq!(finding.severity, "medium");
    assert!(finding.title.contains("Incomplete TCP handshake"));
}

#[test]
fn audit_flags_rst_storm() {
    // 5 RST packets to the same stream — RST storm.
    let packets: Vec<DecodedFrame> = (0..5)
        .map(|_| {
            tcp_packet_with_flags(
                "10.0.0.1",
                "10.0.0.2",
                50000,
                80,
                TcpFlags {
                    rst: true,
                    ..default_flags()
                },
            )
        })
        .collect();

    let capture = tracked_capture(packets);
    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "connection_anomaly" && f.id.starts_with("rst-storm"))
        .expect("rst storm finding");
    assert_eq!(finding.severity, "medium");
    assert!(finding.title.contains("RST storm"));
    assert!(finding.title.contains("5 RST packets"));
}

#[test]
fn audit_flags_half_open_connection() {
    // SYN+ACK seen (handshake), then data packets, but no FIN/RST — half-open.
    let mut packets = vec![
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                syn: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.2",
            "10.0.0.1",
            80,
            50000,
            TcpFlags {
                syn: true,
                ack: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                ack: true,
                ..default_flags()
            },
        ),
    ];
    // Add data packets (ACK+PSH) to exceed the half-open threshold.
    for _ in 0..12 {
        packets.push(tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                ack: true,
                psh: true,
                ..default_flags()
            },
        ));
    }

    let capture = tracked_capture(packets);
    let findings = AuditEngine::audit(&capture);

    let finding = findings
        .iter()
        .find(|f| f.category == "connection_anomaly" && f.id.starts_with("half-open"))
        .expect("half-open finding");
    assert_eq!(finding.severity, "low");
    assert!(finding.title.contains("Half-open connection"));
    assert!(finding.title.contains("no FIN/RST"));
}

#[test]
fn audit_does_not_flag_normal_tcp_connection() {
    // Normal TCP: SYN, SYN+ACK, ACK, data, FIN — no anomalies.
    let packets = vec![
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                syn: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.2",
            "10.0.0.1",
            80,
            50000,
            TcpFlags {
                syn: true,
                ack: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                ack: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                ack: true,
                psh: true,
                ..default_flags()
            },
        ),
        tcp_packet_with_flags(
            "10.0.0.1",
            "10.0.0.2",
            50000,
            80,
            TcpFlags {
                fin: true,
                ack: true,
                ..default_flags()
            },
        ),
    ];

    let capture = tracked_capture(packets);
    let findings = AuditEngine::audit(&capture);

    assert!(
        !findings.iter().any(|f| f.category == "connection_anomaly"),
        "Normal TCP connection should not trigger connection_anomaly findings, but got: {:?}",
        findings
            .iter()
            .filter(|f| f.category == "connection_anomaly")
            .collect::<Vec<_>>()
    );
}
