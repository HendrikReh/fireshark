use fireshark_core::{DecodeIssueKind, IcmpDetail, Layer};
use fireshark_dissectors::{DecodeError, decode_packet};

#[test]
fn ipv4_with_options_parses_through_to_transport() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_options.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert!(packet.layer_names().contains(&"TCP"));
    assert_eq!(packet.transport_ports(), Some((51514, 443)));
}

#[test]
fn decodes_tcp_syn_ack_flags() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_syn_ack.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");
    assert!(tcp.flags.syn);
    assert!(tcp.flags.ack);
    assert!(!tcp.flags.fin);
    assert!(!tcp.flags.rst);
    assert_eq!(tcp.seq, 100);
    assert_eq!(tcp.ack, 2);
    assert_eq!(tcp.window, 65535);
}

#[test]
fn decodes_tcp_rst_flag() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_rst.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");
    assert!(tcp.flags.rst);
    assert!(!tcp.flags.syn);
    assert!(!tcp.flags.ack);
}

#[test]
fn tcp_with_options_skips_option_bytes() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_data_offset_gt5.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");
    assert_eq!(tcp.data_offset, 6);
}

#[test]
fn tcp_data_offset_below_5_is_malformed() {
    // Mutate existing fixture: set TCP data_offset to 4 (0x40 in the high nibble of byte 12 of TCP)
    // TCP header starts at byte 34 (14 eth + 20 ipv4), data_offset is at TCP byte 12 = overall byte 46
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[46] = (4 << 4) | (bytes[46] & 0x0f);

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert!(!packet.layer_names().contains(&"TCP"));
    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
}

#[test]
fn tcp_data_offset_exceeding_buffer_is_truncated() {
    // Mutate existing fixture: set TCP data_offset to 15 (0xF0 in the high nibble)
    // That requires 60 bytes of TCP header, but the TCP payload portion is only 20 bytes
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[46] = (15 << 4) | (bytes[46] & 0x0f);

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert!(!packet.layer_names().contains(&"TCP"));
    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Truncated);
}

#[test]
fn decodes_icmp_echo_reply_detail() {
    let bytes = include_bytes!("../../../fixtures/bytes/icmp_echo_reply.bin");
    let packet = decode_packet(bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Icmp(layer) => Some(layer),
            _ => None,
        })
        .expect("ICMP layer");
    assert_eq!(icmp.type_, 0);
    assert_eq!(icmp.code, 0);
    assert_eq!(
        icmp.detail,
        Some(IcmpDetail::EchoReply {
            identifier: 0x1234,
            sequence: 1,
        })
    );
}

#[test]
fn decodes_icmp_dest_unreachable_detail() {
    let bytes = include_bytes!("../../../fixtures/bytes/icmp_dest_unreachable.bin");
    let packet = decode_packet(bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Icmp(layer) => Some(layer),
            _ => None,
        })
        .expect("ICMP layer");
    assert_eq!(icmp.type_, 3);
    assert_eq!(icmp.code, 4);
    assert_eq!(
        icmp.detail,
        Some(IcmpDetail::DestinationUnreachable { next_hop_mtu: 1500 })
    );
}

#[test]
fn icmp_with_only_4_bytes_has_no_detail() {
    // Take the ICMPv6 fixture and truncate to only 4 bytes of ICMP payload
    // IPv6 header starts at byte 14, payload_length at bytes 18-19
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    // Set IPv6 payload_length to 4 (only 4 bytes of ICMP)
    bytes[18] = 0;
    bytes[19] = 4;

    let packet = decode_packet(&bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Icmp(layer) => Some(layer),
            _ => None,
        })
        .expect("ICMP layer");
    assert!(icmp.detail.is_none());
}

#[test]
fn ethernet_truncated_returns_error() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_truncated.bin");
    let result = decode_packet(bytes);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DecodeError::Truncated { .. }));
}

#[test]
fn ethernet_unknown_ethertype_has_no_upper_layers() {
    // Mutate EtherType to 0xFFFF
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[12] = 0xFF;
    bytes[13] = 0xFF;

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert_eq!(packet.layers().len(), 1);
}

#[test]
fn arp_truncated_payload_returns_error() {
    // Take ARP fixture and truncate to only 24 bytes of ARP payload (need 28)
    // ARP payload starts at byte 14, so 14 + 24 = 38 total bytes
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin");
    let truncated = &bytes[..38];

    let packet = decode_packet(truncated).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(!packet.layer_names().contains(&"ARP"));
    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Truncated);
}

#[test]
fn arp_non_ethernet_hardware_type_is_malformed() {
    // Change hw_type from 1 to 6 (byte 14-15 in the full frame = ARP bytes 0-1)
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin").to_vec();
    bytes[14] = 0;
    bytes[15] = 6;

    let packet = decode_packet(&bytes).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(!packet.layer_names().contains(&"ARP"));
    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
}

#[test]
fn ipv4_ttl_zero_is_valid_parse() {
    // Mutate TTL byte in existing fixture (byte 22 = IPv4 byte 8)
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[22] = 0;

    let packet = decode_packet(&bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");
    assert_eq!(ipv4.ttl, 0);
}

#[test]
fn ipv6_hop_limit_zero_is_valid_parse() {
    // Mutate hop_limit byte in existing fixture (byte 21 = IPv6 byte 7)
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    bytes[21] = 0;

    let packet = decode_packet(&bytes).unwrap();

    let ipv6 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv6(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv6 layer");
    assert_eq!(ipv6.hop_limit, 0);
}

#[test]
fn decodes_tcp_syn_with_dscp() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_syn.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");
    assert_eq!(ipv4.dscp, 8);
    assert_eq!(ipv4.ecn, 0);
    assert_eq!(ipv4.ttl, 128);
    assert!(!ipv4.dont_fragment);

    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");
    assert_eq!(tcp.source_port, 12345);
    assert_eq!(tcp.destination_port, 80);
}

#[test]
fn udp_length_field_parsed_even_when_mismatched() {
    let bytes = include_bytes!("../../../fixtures/bytes/udp_length_mismatch.bin");
    let packet = decode_packet(bytes).unwrap();

    let udp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Udp(layer) => Some(layer),
            _ => None,
        })
        .expect("UDP layer");
    assert_eq!(udp.length, 100);
}

#[test]
fn ipv4_first_fragment_decodes_transport() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_fragment_first.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");
    assert_eq!(ipv4.fragment_offset, 0);
    assert!(ipv4.more_fragments);
    assert!(packet.layer_names().contains(&"TCP"));
}

#[test]
fn ipv4_ttl_zero_fixture_parses() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_ttl_zero.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");
    assert_eq!(ipv4.ttl, 0);
}
