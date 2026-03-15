use fireshark_core::{DecodeIssueKind, Layer};
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_tcp_ports() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(packet.transport_ports(), Some((51514, 443)));
}

#[test]
fn decodes_udp_ports() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(packet.transport_ports(), Some((5353, 53)));
}

#[test]
fn decodes_icmp_layer() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"ICMP"));
}

#[test]
fn ipv4_total_length_ignores_padding_bytes() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[16] = 0;
    bytes[17] = 20;

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert_eq!(packet.transport_ports(), None);
    assert!(packet.issues().is_empty());
}

#[test]
fn ipv4_total_length_reports_truncation() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[16] = 0;
    bytes[17] = 60;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.transport_ports(), Some((51514, 443)));
    assert_eq!(packet.issues().len(), 1);
}

#[test]
fn ipv6_payload_length_ignores_padding_bytes() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    bytes[18] = 0;
    bytes[19] = 0;

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv6"));
    assert!(!packet.layer_names().contains(&"ICMP"));
    assert!(packet.issues().is_empty());
}

#[test]
fn ipv6_payload_length_reports_truncation() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    bytes[18] = 0;
    bytes[19] = 32;

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"ICMP"));
    assert_eq!(packet.issues().len(), 1);
}

#[test]
fn tcp_truncation_offset_accounts_for_ipv4_header() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[16] = 0;
    bytes[17] = 25;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].offset(), 39);
}

#[test]
fn udp_truncation_offset_accounts_for_ipv4_header() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin").to_vec();
    bytes[16] = 0;
    bytes[17] = 22;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].offset(), 36);
}

#[test]
fn icmp_truncation_offset_accounts_for_ipv6_header() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    bytes[18] = 0;
    bytes[19] = 2;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].offset(), 56);
}

#[test]
fn malformed_ipv4_headers_surface_decode_issues() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[14] = 0x65;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
    assert!(!packet.layer_names().contains(&"IPv4"));
    assert_eq!(packet.transport_ports(), None);
}

#[test]
fn invalid_ipv4_ihl_is_reported_as_malformed() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[14] = 0x44;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
    assert!(!packet.layer_names().contains(&"IPv4"));
    assert_eq!(packet.transport_ports(), None);
}

#[test]
fn non_initial_ipv4_fragments_skip_transport_decode() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[20] = 0x20;
    bytes[21] = 0x01;

    let packet = decode_packet(&bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.fragment_offset, 1);
    assert!(ipv4.more_fragments);
    assert_eq!(packet.transport_ports(), None);
    assert!(!packet.layer_names().contains(&"TCP"));
}
