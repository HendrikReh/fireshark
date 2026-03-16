use std::net::Ipv4Addr;

use fireshark_core::Layer;
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_ethernet_arp_layers() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(packet.layer_names().contains(&"ARP"));

    let arp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Arp(layer) => Some(layer),
            _ => None,
        })
        .expect("ARP layer");
    assert_eq!(arp.operation, 1);
}

#[test]
fn decodes_arp_reply() {
    let bytes = include_bytes!("../../../fixtures/bytes/arp_reply.bin");
    let packet = decode_packet(bytes).unwrap();

    let arp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Arp(layer) => Some(layer),
            _ => None,
        })
        .expect("ARP layer");
    assert_eq!(arp.operation, 2);
    assert_eq!(arp.sender_protocol_addr, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(arp.target_protocol_addr, Ipv4Addr::new(192, 168, 1, 2));
}

#[test]
fn decodes_arp_gratuitous() {
    let bytes = include_bytes!("../../../fixtures/bytes/arp_gratuitous.bin");
    let packet = decode_packet(bytes).unwrap();

    let arp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Arp(layer) => Some(layer),
            _ => None,
        })
        .expect("ARP layer");
    assert_eq!(arp.operation, 1);
    assert_eq!(arp.sender_protocol_addr, arp.target_protocol_addr);
    assert_eq!(arp.sender_protocol_addr, Ipv4Addr::new(192, 168, 1, 1));
}
