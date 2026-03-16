use std::net::Ipv4Addr;

use fireshark_core::{
    DecodeIssue, DecodedFrame, EthernetLayer, Frame, Ipv4Layer, Layer, Packet, TcpLayer,
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

    assert!(findings.iter().any(|finding| finding.category == "decode_issues"));
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

    assert!(findings.iter().any(|finding| finding.category == "unknown_traffic"));
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

    assert!(findings.iter().any(|finding| finding.category == "scan_activity"));
}

#[test]
fn audit_flags_suspicious_port_usage() {
    let capture = AnalyzedCapture::from_packets(vec![tcp_packet(
        "10.0.0.1",
        "10.0.0.2",
        23,
        Vec::new(),
    )]);

    let findings = AuditEngine::audit(&capture);

    assert!(findings.iter().any(|finding| finding.category == "suspicious_ports"));
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
                    fragment_offset: 0,
                    more_fragments: false,
                }),
                Layer::Tcp(TcpLayer {
                    source_port: 50_000,
                    destination_port,
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
