use fireshark_core::DecodeIssueKind;
use fireshark_dissectors::decode_packet;

// ---------------------------------------------------------------------------
// IPv4 header checksum
// ---------------------------------------------------------------------------

#[test]
fn valid_ipv4_checksum_produces_no_issues() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_tcp_valid_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert!(packet.layer_names().contains(&"TCP"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    assert!(
        checksum_issues.is_empty(),
        "expected no checksum issues for valid fixture, got {checksum_issues:?}"
    );
}

#[test]
fn bad_ipv4_header_checksum_produces_checksum_mismatch() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_bad_header_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    assert!(
        !checksum_issues.is_empty(),
        "expected ChecksumMismatch for corrupted IPv4 header"
    );
    // The IPv4 header starts at offset 14 (after Ethernet).
    assert_eq!(checksum_issues[0].offset(), 14);
}

#[test]
fn zero_ipv4_checksum_skips_validation() {
    // The original fixture has checksum=0 (NIC offload) — no mismatch expected.
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(
        packet
            .issues()
            .iter()
            .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
            .count(),
        0,
        "checksum=0 should be skipped (NIC offload)"
    );
}

// ---------------------------------------------------------------------------
// TCP checksum
// ---------------------------------------------------------------------------

#[test]
fn valid_tcp_checksum_produces_no_issues() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_tcp_valid_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"TCP"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    assert!(
        checksum_issues.is_empty(),
        "expected no checksum issues for valid TCP fixture, got {checksum_issues:?}"
    );
}

#[test]
fn bad_tcp_checksum_produces_checksum_mismatch() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_tcp_bad_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"TCP"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    // Should have at least one checksum mismatch for the TCP layer.
    // (IPv4 header checksum is valid in this fixture.)
    assert!(
        !checksum_issues.is_empty(),
        "expected ChecksumMismatch for corrupted TCP checksum"
    );
    // TCP transport offset is 34 (14 Ethernet + 20 IPv4).
    assert!(
        checksum_issues.iter().any(|i| i.offset() == 34),
        "expected ChecksumMismatch at transport offset 34"
    );
}

#[test]
fn zero_tcp_checksum_skips_validation() {
    // The original fixture has checksum=0 — no transport mismatch expected.
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(
        packet
            .issues()
            .iter()
            .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
            .count(),
        0,
        "TCP checksum=0 should be skipped"
    );
}

// ---------------------------------------------------------------------------
// UDP checksum
// ---------------------------------------------------------------------------

#[test]
fn valid_udp_checksum_produces_no_issues() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_udp_valid_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"UDP"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    assert!(
        checksum_issues.is_empty(),
        "expected no checksum issues for valid UDP fixture, got {checksum_issues:?}"
    );
}

#[test]
fn bad_udp_checksum_produces_checksum_mismatch() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_udp_bad_checksum.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"UDP"));
    let checksum_issues: Vec<_> = packet
        .issues()
        .iter()
        .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
        .collect();
    assert!(
        !checksum_issues.is_empty(),
        "expected ChecksumMismatch for corrupted UDP checksum"
    );
    // UDP transport offset is 34 (14 Ethernet + 20 IPv4).
    assert!(
        checksum_issues.iter().any(|i| i.offset() == 34),
        "expected ChecksumMismatch at transport offset 34"
    );
}

#[test]
fn zero_udp_checksum_skips_validation() {
    // The original fixture has checksum=0 — no mismatch expected.
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(
        packet
            .issues()
            .iter()
            .filter(|i| *i.kind() == DecodeIssueKind::ChecksumMismatch)
            .count(),
        0,
        "UDP checksum=0 means 'not computed' — should be skipped"
    );
}
