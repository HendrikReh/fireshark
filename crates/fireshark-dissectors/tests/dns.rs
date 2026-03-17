use std::net::Ipv4Addr;

use fireshark_core::{DnsAnswerData, Layer, LayerSpan};
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_dns_query() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();

    let dns = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Dns(layer) => Some(layer),
            _ => None,
        })
        .expect("DNS layer");

    assert_eq!(dns.transaction_id, 0x1234);
    assert!(!dns.is_response);
    assert_eq!(dns.opcode, 0);
    assert_eq!(dns.question_count, 1);
    assert_eq!(dns.answer_count, 0);
    assert_eq!(dns.query_name.as_deref(), Some("example.com"));
    assert_eq!(dns.query_type, Some(1)); // A record
    assert!(dns.answers.is_empty());
}

#[test]
fn decodes_dns_layer_names() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();

    let names: Vec<&str> = packet.layers().iter().map(|l| l.name()).collect();
    assert_eq!(names, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
}

#[test]
fn dns_truncated_header() {
    // Full fixture is 71 bytes. Ethernet(14) + IPv4(20) + UDP(8) = 42 bytes of headers.
    // DNS starts at offset 42. Give only 6 bytes of DNS (need 12).
    // We modify the IPv4 total_len so the IP payload is shorter.
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin").to_vec();

    // Set IPv4 total_len = 20 + 8 + 6 = 34 (only 6 bytes of DNS payload)
    let short_total: u16 = 34;
    bytes[16] = (short_total >> 8) as u8;
    bytes[17] = (short_total & 0xFF) as u8;

    let packet = decode_packet(&bytes).unwrap();

    // Should have Ethernet + IPv4 + UDP but NO DNS (truncated)
    assert!(packet.layer_names().contains(&"UDP"));
    assert!(!packet.layer_names().contains(&"DNS"));
    // Should have a truncation issue
    assert!(!packet.issues().is_empty());
}

#[test]
fn dns_with_compression_pointer_yields_none_name() {
    // Build a minimal DNS message where the question name starts with a compression pointer.
    // 12-byte header + pointer(2) + qtype(2) + qclass(2) = 18 bytes DNS payload
    let dns_bytes: Vec<u8> = vec![
        // DNS header (12 bytes)
        0xAB, 0xCD, // transaction_id
        0x01, 0x00, // flags: query, RD=1
        0x00, 0x01, // qdcount=1
        0x00, 0x00, // ancount=0
        0x00, 0x00, // nscount=0
        0x00, 0x00, // arcount=0
        // Question: compression pointer 0xC00C, type=A, class=IN
        0xC0, 0x0C, // pointer to offset 12 (doesn't matter, we don't follow)
        0x00, 0x01, // type=A
        0x00, 0x01, // class=IN
    ];

    // parse directly (not through full pipeline)
    let layer = fireshark_dissectors::decode_packet(&build_dns_frame(&dns_bytes)).unwrap();
    let dns = layer
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .expect("DNS layer");

    // Compression pointer at start means empty name -> None
    assert_eq!(dns.query_name, None);
    assert_eq!(dns.query_type, Some(1));
}

#[test]
fn dns_span_covers_full_payload() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();

    assert_eq!(spans.len(), 4, "Ethernet + IPv4 + UDP + DNS");

    // DNS span: starts after UDP header (offset 42), covers remaining 29 bytes
    assert_eq!(
        spans[3],
        LayerSpan {
            offset: 42,
            len: 29
        }
    );
}

#[test]
fn dns_respects_declared_udp_payload_length() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin").to_vec();
    bytes[38] = 0;
    bytes[39] = 8;

    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.layer_names(), vec!["Ethernet", "IPv4", "UDP"]);
}

#[test]
fn decodes_dns_response_with_a_record() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns_response.bin");
    let packet = decode_packet(bytes).unwrap();

    let dns = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Dns(layer) => Some(layer),
            _ => None,
        })
        .expect("DNS layer");

    assert!(dns.is_response);
    assert_eq!(dns.answer_count, 1);
    assert_eq!(dns.answers.len(), 1);

    let answer = &dns.answers[0];
    assert_eq!(answer.record_type, 1);
    assert_eq!(answer.ttl, 300);
    assert_eq!(
        answer.data,
        DnsAnswerData::A(Ipv4Addr::new(93, 184, 216, 34))
    );
}

#[test]
fn dns_query_has_empty_answers() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();

    let dns = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Dns(layer) => Some(layer),
            _ => None,
        })
        .expect("DNS layer");

    assert!(!dns.is_response);
    assert!(dns.answers.is_empty());
}

/// Helper: wrap raw DNS bytes in Ethernet + IPv4 + UDP headers.
fn build_dns_frame(dns_payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0x0a, 0xbb]); // src
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let ip_total_len = (20 + 8 + dns_payload.len()) as u16;
    frame.push(0x45); // version=4, ihl=5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&ip_total_len.to_be_bytes()); // total length
    frame.extend_from_slice(&[0x00, 0x00]); // identification
    frame.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag_offset=0
    frame.push(64); // TTL
    frame.push(17); // protocol=UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(&[192, 0, 2, 10]); // src IP
    frame.extend_from_slice(&[198, 51, 100, 20]); // dst IP

    // UDP header (8 bytes)
    let udp_len = (8 + dns_payload.len()) as u16;
    frame.extend_from_slice(&12345u16.to_be_bytes()); // src port
    frame.extend_from_slice(&53u16.to_be_bytes()); // dst port
    frame.extend_from_slice(&udp_len.to_be_bytes()); // length
    frame.extend_from_slice(&[0x00, 0x00]); // checksum

    // DNS payload
    frame.extend_from_slice(dns_payload);

    frame
}
