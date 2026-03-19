//! Tests for IPv6 extension header walking, fragment handling,
//! checksum validation, and AH/ESP terminal behavior.

use fireshark_core::DecodeIssueKind;
use fireshark_dissectors::decode_packet;

/// Build a minimal Ethernet + IPv6 frame with the given next_header,
/// extension headers, and transport payload.
fn build_ipv6_frame(next_header: u8, ext_and_payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&[0x00; 6]); // dst MAC
    frame.extend_from_slice(&[0x00; 6]); // src MAC
    frame.extend_from_slice(&[0x86, 0xdd]); // EtherType = IPv6

    // IPv6 header (40 bytes)
    let payload_len = ext_and_payload.len() as u16;
    frame.push(0x60); // version=6, traffic_class high nibble=0
    frame.push(0x00); // traffic_class low + flow_label high
    frame.extend_from_slice(&[0x00, 0x00]); // flow_label low
    frame.extend_from_slice(&payload_len.to_be_bytes()); // payload length
    frame.push(next_header);
    frame.push(64); // hop limit
    // src: ::1
    frame.extend_from_slice(&[0; 15]);
    frame.push(1);
    // dst: ::2
    frame.extend_from_slice(&[0; 15]);
    frame.push(2);

    // Extension headers + transport payload
    frame.extend_from_slice(ext_and_payload);

    frame
}

/// Build a minimal UDP header (8 bytes) with the given ports and zero checksum.
fn udp_header(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&src_port.to_be_bytes());
    hdr.extend_from_slice(&dst_port.to_be_bytes());
    hdr.extend_from_slice(&8u16.to_be_bytes()); // length = 8 (header only)
    hdr.extend_from_slice(&0u16.to_be_bytes()); // checksum = 0
    hdr
}

// --- AH/ESP stop the extension header walk ---

#[test]
fn ah_stops_extension_header_walk() {
    // next_header=51 (AH) should NOT be skipped — AH is the terminal protocol.
    // The payload after IPv6 header is treated as AH, not parsed as transport.
    let payload = vec![0u8; 16]; // arbitrary AH-like bytes
    let frame = build_ipv6_frame(51, &payload);
    let packet = decode_packet(&frame).unwrap();

    // Should have Ethernet + IPv6 but NOT TCP/UDP/ICMP
    assert!(packet.layer_names().contains(&"IPv6"));
    assert!(!packet.layer_names().contains(&"TCP"));
    assert!(!packet.layer_names().contains(&"UDP"));
}

#[test]
fn esp_stops_extension_header_walk() {
    // next_header=50 (ESP) should NOT be skipped.
    let payload = vec![0u8; 16];
    let frame = build_ipv6_frame(50, &payload);
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"IPv6"));
    assert!(!packet.layer_names().contains(&"TCP"));
    assert!(!packet.layer_names().contains(&"UDP"));
}

// --- IPv6 Hop-by-Hop extension header is skipped ---

#[test]
fn hop_by_hop_extension_skipped_to_reach_udp() {
    // IPv6 next_header=0 (Hop-by-Hop), then ext header pointing to UDP (17).
    // Hop-by-Hop: next_header=17, hdr_ext_len=0 → (0+1)*8 = 8 bytes total
    let mut ext_and_payload = Vec::new();
    // Hop-by-Hop extension header (8 bytes)
    ext_and_payload.push(17); // next_header = UDP
    ext_and_payload.push(0); // hdr_ext_len = 0 → 8 bytes
    ext_and_payload.extend_from_slice(&[0u8; 6]); // padding
    // UDP header
    ext_and_payload.extend_from_slice(&udp_header(5353, 53));

    let frame = build_ipv6_frame(0, &ext_and_payload);
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"IPv6"));
    assert!(packet.layer_names().contains(&"UDP"));
}

// --- IPv6 Fragment header handling ---

#[test]
fn ipv6_first_fragment_skips_checksum_validation() {
    // Fragment header with offset=0, MF=1 (first fragment).
    // Transport checksum should NOT be validated.
    let mut ext_and_payload = Vec::new();
    // Fragment header (8 bytes): next_header=17 (UDP)
    ext_and_payload.push(17); // next_header = UDP
    ext_and_payload.push(0); // reserved
    ext_and_payload.extend_from_slice(&0x0001u16.to_be_bytes()); // offset=0, MF=1
    ext_and_payload.extend_from_slice(&0u32.to_be_bytes()); // identification
    // UDP header with checksum=0 (would be flagged if validation ran)
    ext_and_payload.extend_from_slice(&udp_header(1234, 53));

    let frame = build_ipv6_frame(44, &ext_and_payload);
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"UDP"));
    // No checksum mismatch issue — validation was skipped for fragment
    let has_checksum_issue = packet
        .issues()
        .iter()
        .any(|i| matches!(i.kind(), DecodeIssueKind::ChecksumMismatch));
    assert!(
        !has_checksum_issue,
        "first fragment should not trigger checksum validation"
    );
}

#[test]
fn ipv6_atomic_fragment_validates_checksum() {
    // Atomic fragment: offset=0, MF=0.
    // RFC 6946 says it is processed in isolation, so transport checksum
    // validation should still run on the full payload it carries.
    let mut ext_and_payload = Vec::new();
    ext_and_payload.push(17); // next_header = UDP
    ext_and_payload.push(0); // reserved
    ext_and_payload.extend_from_slice(&0x0000u16.to_be_bytes()); // offset=0, MF=0
    ext_and_payload.extend_from_slice(&0u32.to_be_bytes()); // identification
    ext_and_payload.extend_from_slice(&udp_header(1234, 53));

    let frame = build_ipv6_frame(44, &ext_and_payload);
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"UDP"));
    let has_checksum_issue = packet
        .issues()
        .iter()
        .any(|i| matches!(i.kind(), DecodeIssueKind::ChecksumMismatch));
    assert!(
        has_checksum_issue,
        "atomic fragment should still validate the UDP checksum"
    );
}

#[test]
fn ipv6_non_initial_fragment_skips_transport_decode() {
    // Fragment header with offset=185 (non-zero), MF=1.
    // Transport decode should be suppressed entirely.
    let mut ext_and_payload = Vec::new();
    // Fragment header (8 bytes): next_header=17 (UDP)
    ext_and_payload.push(17); // next_header = UDP
    ext_and_payload.push(0); // reserved
    let frag_offset_flags: u16 = (185 << 3) | 1; // offset=185, MF=1
    ext_and_payload.extend_from_slice(&frag_offset_flags.to_be_bytes());
    ext_and_payload.extend_from_slice(&0u32.to_be_bytes()); // identification
    // Fragment payload (NOT a UDP header — just data)
    ext_and_payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);

    let frame = build_ipv6_frame(44, &ext_and_payload);
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"IPv6"));
    // Should NOT have a UDP layer (non-initial fragment)
    assert!(
        !packet.layer_names().contains(&"UDP"),
        "non-initial fragment should not decode transport"
    );
}

// --- IPv6 UDP checksum=0 is invalid ---

#[test]
fn ipv6_udp_zero_checksum_flagged() {
    // IPv6 UDP with checksum=0 should produce a ChecksumMismatch issue
    // (RFC 8200 §8.1: zero checksum is invalid for IPv6 UDP).
    let frame = build_ipv6_frame(17, &udp_header(1234, 53));
    let packet = decode_packet(&frame).unwrap();

    assert!(packet.layer_names().contains(&"UDP"));
    let has_checksum_issue = packet
        .issues()
        .iter()
        .any(|i| matches!(i.kind(), DecodeIssueKind::ChecksumMismatch));
    assert!(
        has_checksum_issue,
        "IPv6 UDP checksum=0 should be flagged as invalid"
    );
}
