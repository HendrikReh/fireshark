use fireshark_core::{DecodeIssueKind, IcmpDetail, Layer, LayerSpan};
use fireshark_dissectors::decode_packet;

#[test]
fn decode_packet_produces_udp_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();
    assert_eq!(spans.len(), 3, "Ethernet + IPv4 + UDP");
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 });
    assert_eq!(spans[2], LayerSpan { offset: 34, len: 8 }); // UDP is 8 bytes
}

#[test]
fn decode_packet_produces_icmpv6_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();
    assert_eq!(spans.len(), 3, "Ethernet + IPv6 + ICMP");
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 });
    assert_eq!(
        spans[1],
        LayerSpan {
            offset: 14,
            len: 40
        }
    ); // IPv6 is 40 bytes
    assert_eq!(spans[2], LayerSpan { offset: 54, len: 8 }); // ICMPv6 echo has 8 bytes
}

#[test]
fn decodes_tcp_ports() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(packet.transport_ports(), Some((51514, 443)));

    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");
    assert_eq!(tcp.seq, 1);
    assert_eq!(tcp.ack, 0);
    assert_eq!(tcp.data_offset, 5);
    assert!(tcp.flags.syn);
    assert!(!tcp.flags.ack);
    assert!(!tcp.flags.fin);
    assert!(!tcp.flags.rst);
    assert_eq!(tcp.window, 1024);
}

#[test]
fn decodes_ipv4_fields() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");
    assert_eq!(ipv4.ttl, 64);
    assert_eq!(ipv4.identification, 1);
    assert_eq!(ipv4.dscp, 0);
    assert_eq!(ipv4.ecn, 0);
    assert!(ipv4.dont_fragment);
    assert_eq!(ipv4.fragment_offset, 0);
    assert_eq!(ipv4.header_checksum, 0);
}

#[test]
fn decodes_udp_ports() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert_eq!(packet.transport_ports(), Some((5353, 53)));

    let udp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Udp(layer) => Some(layer),
            _ => None,
        })
        .expect("UDP layer");
    assert_eq!(udp.length, 8);
}

#[test]
fn decodes_icmp_layer() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"ICMP"));

    let icmp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Icmp(layer) => Some(layer),
            _ => None,
        })
        .expect("ICMP layer");
    assert_eq!(icmp.type_, 128);
    assert!(matches!(icmp.detail, Some(IcmpDetail::Other { .. })));
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

#[test]
fn decodes_ipv6_fields() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv6 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv6(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv6 layer");
    assert_eq!(ipv6.traffic_class, 0);
    assert_eq!(ipv6.flow_label, 0);
    assert_eq!(ipv6.hop_limit, 64);
}

#[test]
fn decode_packet_produces_dns_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();
    assert_eq!(spans.len(), 4, "Ethernet + IPv4 + UDP + DNS");
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 }); // Ethernet
    assert_eq!(
        spans[1],
        LayerSpan {
            offset: 14,
            len: 20
        }
    ); // IPv4
    assert_eq!(spans[2], LayerSpan { offset: 34, len: 8 }); // UDP
    assert_eq!(
        spans[3],
        LayerSpan {
            offset: 42,
            len: 29
        }
    ); // DNS
}

#[test]
fn decode_packet_produces_layer_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();
    assert_eq!(spans.len(), 3, "Ethernet + IPv4 + TCP");
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 });
    assert_eq!(
        spans[1],
        LayerSpan {
            offset: 14,
            len: 20
        }
    );
    assert_eq!(
        spans[2],
        LayerSpan {
            offset: 34,
            len: 20
        }
    );
}
