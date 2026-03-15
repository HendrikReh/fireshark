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
