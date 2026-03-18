mod support;

use fireshark_backend::{BackendCapture, BackendKind, compare};

#[test]
fn compare_identical_captures_has_no_differences() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let a = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let b = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    let result = compare(&a, &b);

    assert_eq!(result.a_packet_count, result.b_packet_count);
    assert_eq!(result.a_stream_count, result.b_stream_count);
    assert!(result.new_hosts.is_empty());
    assert!(result.missing_hosts.is_empty());
    assert!(result.new_protocols.is_empty());
    assert!(result.missing_protocols.is_empty());
    assert!(result.new_ports.is_empty());
    assert!(result.missing_ports.is_empty());
}

#[test]
fn compare_different_captures_reports_new_and_missing() {
    let root = support::repo_root();
    let a = BackendCapture::open(
        root.join("fixtures/smoke/minimal.pcap"),
        BackendKind::Native,
    )
    .unwrap();
    let b = BackendCapture::open(
        root.join("fixtures/smoke/fuzz-2006-06-26-2594.pcap"),
        BackendKind::Native,
    )
    .unwrap();

    let result = compare(&a, &b);

    assert_ne!(result.a_packet_count, result.b_packet_count);
    // With different captures, at least one direction should have differences
    let has_diffs = !result.new_hosts.is_empty()
        || !result.missing_hosts.is_empty()
        || !result.new_protocols.is_empty()
        || !result.missing_protocols.is_empty()
        || !result.new_ports.is_empty()
        || !result.missing_ports.is_empty();
    assert!(
        has_diffs,
        "different captures should produce at least one difference"
    );
}

#[test]
fn compare_is_asymmetric() {
    let root = support::repo_root();
    let a = BackendCapture::open(
        root.join("fixtures/smoke/minimal.pcap"),
        BackendKind::Native,
    )
    .unwrap();
    let b = BackendCapture::open(
        root.join("fixtures/smoke/fuzz-2006-06-26-2594.pcap"),
        BackendKind::Native,
    )
    .unwrap();

    let ab = compare(&a, &b);
    let ba = compare(&b, &a);

    // new_hosts in A->B should be missing_hosts in B->A
    assert_eq!(ab.new_hosts, ba.missing_hosts);
    assert_eq!(ab.missing_hosts, ba.new_hosts);
    assert_eq!(ab.new_protocols, ba.missing_protocols);
    assert_eq!(ab.missing_protocols, ba.new_protocols);
    assert_eq!(ab.new_ports, ba.missing_ports);
    assert_eq!(ab.missing_ports, ba.new_ports);
}
