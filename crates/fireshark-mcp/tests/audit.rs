use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use fireshark_core::{
    DecodeIssue, DecodedFrame, EthernetLayer, Frame, Ipv4Layer, Layer, Packet, TcpFlags, TcpLayer,
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
