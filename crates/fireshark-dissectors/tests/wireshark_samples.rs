use fireshark_core::Layer;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

mod support;

/// Wireshark dns.cap: Real-world DNS traffic with TXT, MX responses
/// and name compression. Validates the DNS dissector against production
/// traffic patterns.
#[test]
fn wireshark_dns_parses_all_packets_without_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut packet_count = 0;
    let mut issue_count = 0;
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for decoded in &packets {
        packet_count += 1;
        issue_count += decoded.packet().issues().len();
        // Every packet should have at least Ethernet + IPv4 + UDP + DNS
        assert!(
            decoded.packet().layers().len() >= 4,
            "packet {packet_count} should have at least 4 layers, got {}",
            decoded.packet().layers().len()
        );
    }
    assert_eq!(packet_count, 8);
    assert_eq!(
        issue_count, 0,
        "real-world DNS should parse without decode issues"
    );
}

#[test]
fn wireshark_dns_response_has_txt_answer() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Packet 2 is a DNS response for google.com TXT
    let dns = packets[1]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .expect("DNS layer");

    assert!(dns.is_response);
    assert_eq!(dns.answer_count, 1);
    assert!(!dns.answers.is_empty());
    // TXT record type is 16
    assert_eq!(dns.answers[0].record_type, 16);
}

#[test]
fn wireshark_dns_response_has_mx_answers() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Packet 4 is a DNS response for google.com MX (6 answers)
    let dns = packets[3]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .expect("DNS layer");

    assert!(dns.is_response);
    assert_eq!(dns.answer_count, 6);
    // MX record type is 15
    assert!(dns.answers.iter().all(|a| a.record_type == 15));
}

#[test]
fn wireshark_dns_query_names_use_real_domains() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Packet 1 is a query for google.com
    let dns = packets[0]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .expect("DNS layer");

    assert!(!dns.is_response);
    assert_eq!(dns.query_name.as_deref(), Some("google.com"));
}

/// Wireshark ipv4frags.pcap: Real IPv4 fragmentation with ICMP echo.
/// Packet 1 = first fragment (MF=1), Packet 2 = continuation fragment,
/// Packet 3 = reassembled response.
#[test]
fn wireshark_ipv4frags_first_fragment_has_icmp() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-ipv4frags.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(packets.len(), 3);

    // Packet 1: first fragment with MF=1, offset=0, has ICMP
    let ipv4 = packets[0]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(ip) => Some(ip),
            _ => None,
        })
        .expect("IPv4 layer");
    assert!(ipv4.more_fragments);
    assert_eq!(ipv4.fragment_offset, 0);
    assert!(packets[0].packet().layer_names().contains(&"ICMP"));
}

#[test]
fn wireshark_ipv4frags_continuation_fragment_skips_transport() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-ipv4frags.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Packet 2: continuation fragment (offset != 0), transport skipped
    let ipv4 = packets[1]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(ip) => Some(ip),
            _ => None,
        })
        .expect("IPv4 layer");
    assert!(!ipv4.more_fragments);
    assert!(ipv4.fragment_offset > 0);
    // Transport layer should be skipped for non-initial fragments
    assert!(!packets[1].packet().layer_names().contains(&"ICMP"));
}

#[test]
fn wireshark_ipv4frags_no_decode_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-ipv4frags.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = fireshark_core::Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for decoded in &packets {
        assert!(
            decoded.packet().issues().is_empty(),
            "real-world IPv4 fragments should parse without issues"
        );
    }
}
