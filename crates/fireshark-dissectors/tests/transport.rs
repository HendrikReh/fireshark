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
