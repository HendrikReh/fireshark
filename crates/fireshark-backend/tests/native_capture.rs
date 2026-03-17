mod support;

use fireshark_backend::{BackendCapture, BackendKind};

#[test]
fn native_backend_opens_minimal_fixture() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    assert_eq!(capture.packet_count(), 1);
    assert_eq!(capture.backend_kind(), BackendKind::Native);
}

#[test]
fn native_backend_populates_summary_fields() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    let packet = capture.packet(0).expect("should have at least one packet");
    assert!(!packet.summary.protocol.is_empty());
    assert!(!packet.summary.source.is_empty());
    assert!(!packet.summary.destination.is_empty());
    assert!(packet.summary.length > 0);
}

#[test]
fn native_backend_populates_protocol_counts() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    assert!(!capture.protocol_counts().is_empty());
}

#[test]
fn native_backend_populates_layers() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    let packet = capture.packet(0).expect("should have at least one packet");
    assert!(!packet.layers.is_empty());
}

#[test]
fn tshark_backend_opens_minimal_fixture() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    assert_eq!(capture.packet_count(), 1);
    assert_eq!(capture.backend_kind(), BackendKind::Tshark);
}

#[test]
fn tshark_backend_populates_summary_fields() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    let packet = capture.packet(0).expect("should have at least one packet");
    assert!(!packet.summary.protocol.is_empty());
    assert!(!packet.summary.source.is_empty());
    assert!(!packet.summary.destination.is_empty());
    assert!(packet.summary.length > 0);
}

#[test]
fn tshark_backend_populates_protocol_counts() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    assert!(!capture.protocol_counts().is_empty());
}

#[test]
fn tshark_backend_capabilities_are_limited() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    let caps = capture.capabilities();
    assert!(!caps.supports_streams);
    assert!(!caps.supports_decode_issues);
    assert!(!caps.supports_native_filter);
    assert!(!caps.supports_layer_spans);
    assert!(!caps.supports_audit);
}

#[test]
fn tshark_backend_handles_multi_packet_capture() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    assert!(capture.packet_count() > 1);
}

/// Check if tshark is available on this system.
fn tshark_available() -> bool {
    fireshark_tshark::discover().is_ok()
}

#[test]
fn native_backend_capabilities_are_complete() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = BackendCapture::open(&fixture, BackendKind::Native).unwrap();

    let caps = capture.capabilities();
    assert!(caps.supports_streams);
    assert!(caps.supports_decode_issues);
    assert!(caps.supports_native_filter);
    assert!(caps.supports_layer_spans);
    assert!(caps.supports_audit);
}
