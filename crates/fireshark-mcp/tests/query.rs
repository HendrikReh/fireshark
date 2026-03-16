mod support;

use fireshark_mcp::analysis::AnalyzedCapture;
use fireshark_mcp::query::{get_packet, list_packets};

#[test]
fn list_packets_returns_packet_summaries() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packets = list_packets(&capture, 0, 10, None, None);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
}

#[test]
fn get_packet_returns_layers_and_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packet = get_packet(&capture, 0).unwrap();

    assert!(!packet.layers.is_empty());
    assert!(packet.issues.is_empty());
}
