mod support;

use fireshark_mcp::AnalyzedCapture;

#[test]
fn open_capture_decodes_minimal_fixture() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let capture = AnalyzedCapture::open(&fixture).unwrap();

    assert_eq!(capture.packet_count(), 1);
    assert_eq!(capture.protocol_counts().get("TCP"), Some(&1));
}
