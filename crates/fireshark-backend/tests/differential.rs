mod support;

use fireshark_backend::{BackendCapture, BackendKind};

fn has_tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn native_and_tshark_agree_on_packet_count() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();
    assert_eq!(native.packet_count(), tshark.packet_count());
}

#[test]
fn native_and_tshark_agree_on_protocol() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();
    // Protocol should be TCP for both
    assert_eq!(
        native.packet(0).unwrap().summary.protocol,
        tshark.packet(0).unwrap().summary.protocol
    );
}

#[test]
fn native_and_tshark_agree_on_fuzz_fixture_packet_count() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();
    assert_eq!(native.packet_count(), tshark.packet_count());
}

#[test]
fn native_and_tshark_agree_on_source_endpoint() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    let native_src = &native.packet(0).unwrap().summary.source;
    let tshark_src = &tshark.packet(0).unwrap().summary.source;
    // Both should report the same source IP (ignoring port differences)
    assert!(
        native_src.starts_with(
            &tshark_src
                .split(':')
                .next()
                .unwrap_or(tshark_src)
                .to_string()
        ) || tshark_src.starts_with(
            &native_src
                .split(':')
                .next()
                .unwrap_or(native_src)
                .to_string()
        ),
        "source endpoints should share an IP prefix: native={native_src}, tshark={tshark_src}"
    );
}

#[test]
fn native_and_tshark_agree_on_destination_endpoint() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();

    let native_dst = &native.packet(0).unwrap().summary.destination;
    let tshark_dst = &tshark.packet(0).unwrap().summary.destination;
    // Both should report the same destination IP (ignoring port differences)
    assert!(
        native_dst.starts_with(
            &tshark_dst
                .split(':')
                .next()
                .unwrap_or(tshark_dst)
                .to_string()
        ) || tshark_dst.starts_with(
            &native_dst
                .split(':')
                .next()
                .unwrap_or(native_dst)
                .to_string()
        ),
        "destination endpoints should share an IP prefix: native={native_dst}, tshark={tshark_dst}"
    );
}

#[test]
fn native_and_tshark_agree_on_dns_packet_count() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let native = BackendCapture::open(&fixture, BackendKind::Native).unwrap();
    let tshark = BackendCapture::open(&fixture, BackendKind::Tshark).unwrap();
    assert_eq!(native.packet_count(), tshark.packet_count());
}
