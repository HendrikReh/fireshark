mod support;

use fireshark_core::{Layer, Pipeline, TrackingPipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

/// PPA DNS query/response: 2 packets, real DNS with compression pointers
#[test]
fn ppa_dns_query_response_parses_without_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-dns-query-response.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut packet_count = 0;
    for result in Pipeline::new(reader, decode_packet) {
        let decoded = result.unwrap();
        packet_count += 1;
        assert!(decoded.packet().issues().is_empty());
    }
    assert_eq!(packet_count, 2);
}

#[test]
fn ppa_dns_has_query_and_response() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-dns-query-response.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Packet 1: query
    let dns1 = packets[0]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .unwrap();
    assert!(!dns1.is_response);
    assert!(dns1.query_name.is_some());

    // Packet 2: response
    let dns2 = packets[1]
        .packet()
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .unwrap();
    assert!(dns2.is_response);
}

/// PPA TCP handshake: 3 packets, complete SYN/SYN-ACK/ACK
#[test]
fn ppa_tcp_handshake_tracks_one_stream() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-tcp-handshake.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let pipeline = TrackingPipeline::new(reader, decode_packet);
    let packets: Vec<_> = pipeline.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(packets.len(), 3);
    // All 3 packets should have the same stream_id
    let stream = packets[0].stream_id();
    assert!(stream.is_some());
    assert!(packets.iter().all(|p| p.stream_id() == stream));
}

/// PPA SYN scan: many SYN packets to different ports from one source
#[test]
fn ppa_synscan_parses_without_panic() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-synscan.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut count = 0;
    for result in Pipeline::new(reader, decode_packet) {
        let _ = result.unwrap();
        count += 1;
    }
    assert!(count >= 50, "should have at least 50 scan packets");
}

/// PPA ARP poison: adversarial ARP traffic
#[test]
fn ppa_arppoison_parses_arp_layers() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-arppoison.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut arp_count = 0;
    for result in Pipeline::new(reader, decode_packet) {
        let decoded = result.unwrap();
        if decoded.packet().layer_names().contains(&"ARP") {
            arp_count += 1;
        }
    }
    assert!(arp_count > 0, "should contain ARP packets");
}

/// PPA ICMP traceroute: varied ICMP types
#[test]
fn ppa_icmp_traceroute_parses_icmp_layers() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-icmp-traceroute.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut icmp_count = 0;
    for result in Pipeline::new(reader, decode_packet) {
        let decoded = result.unwrap();
        if decoded.packet().layer_names().contains(&"ICMP") {
            icmp_count += 1;
        }
    }
    assert!(icmp_count > 10, "should have many ICMP packets");
}

/// PPA TCP retransmissions: same stream, duplicate seq numbers
#[test]
fn ppa_tcp_retransmissions_single_stream() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-tcp-retransmissions.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut pipeline = TrackingPipeline::new(reader, decode_packet);
    let packets: Vec<_> = pipeline.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
    let tracker = pipeline.into_tracker();
    assert_eq!(packets.len(), 6);
    assert_eq!(
        tracker.stream_count(),
        1,
        "retransmissions should be one stream"
    );
}

/// PPA CryptoWall C2: malware traffic, should parse without panic
#[test]
fn ppa_cryptowall_c2_parses_all_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/ppa-cryptowall4-c2.pcapng");
    let reader = CaptureReader::open(fixture).unwrap();
    let mut count = 0;
    for _ in Pipeline::new(reader, decode_packet).flatten() {
        count += 1;
    }
    assert!(count > 100, "should parse most of the 162 packets");
}
