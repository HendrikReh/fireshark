use fireshark_dissectors::decode_packet;

#[test]
fn decodes_ethernet_arp_layers() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(packet.layer_names().contains(&"ARP"));
}
