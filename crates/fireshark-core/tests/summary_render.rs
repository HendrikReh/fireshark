use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use fireshark_core::{
    ArpLayer, Frame, Ipv4Layer, Ipv6Layer, Layer, Packet, PacketSummary, TcpFlags, TcpLayer,
    UdpLayer,
};

#[test]
fn summary_renders_endpoints_for_tcp_packets() {
    let packet = Packet::new(
        vec![
            Layer::Ipv4(Ipv4Layer {
                source: Ipv4Addr::new(192, 0, 2, 10),
                destination: Ipv4Addr::new(198, 51, 100, 20),
                protocol: 6,
                ttl: 64,
                identification: 1,
                dscp: 0,
                ecn: 0,
                dont_fragment: true,
                fragment_offset: 0,
                more_fragments: false,
                header_checksum: 0,
            }),
            Layer::Tcp(TcpLayer {
                source_port: 51514,
                destination_port: 443,
                seq: 1,
                ack: 0,
                data_offset: 5,
                flags: TcpFlags {
                    fin: false,
                    syn: true,
                    rst: false,
                    psh: false,
                    ack: false,
                    urg: false,
                    ece: false,
                    cwr: false,
                },
                window: 1024,
            }),
        ],
        vec![],
    );

    let frame = Frame::builder()
        .captured_len(60)
        .timestamp(Duration::from_secs(1_700_000_000))
        .protocol("TCP")
        .build();

    let summary = PacketSummary::from_packet(&packet, &frame);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
    assert_eq!(summary.source, "192.0.2.10:51514");
    assert_eq!(summary.destination, "198.51.100.20:443");
    assert_eq!(summary.timestamp, Some(Duration::from_secs(1_700_000_000)));
}

#[test]
fn summary_renders_arp_endpoints() {
    let packet = Packet::new(
        vec![Layer::Arp(ArpLayer {
            operation: 1,
            sender_protocol_addr: Ipv4Addr::new(192, 168, 1, 1),
            target_protocol_addr: Ipv4Addr::new(192, 168, 1, 2),
        })],
        vec![],
    );
    let frame = Frame::builder().captured_len(42).protocol("ARP").build();
    let summary = PacketSummary::from_packet(&packet, &frame);

    assert_eq!(summary.source, "192.168.1.1");
    assert_eq!(summary.destination, "192.168.1.2");
    assert_eq!(summary.protocol, "ARP");
}

#[test]
fn summary_brackets_ipv6_without_ports() {
    let packet = Packet::new(
        vec![Layer::Ipv6(Ipv6Layer {
            source: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            destination: "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            next_header: 59, // No Next Header
            traffic_class: 0,
            flow_label: 0,
            hop_limit: 64,
        })],
        vec![],
    );
    let frame = Frame::builder().captured_len(54).protocol("IPv6").build();
    let summary = PacketSummary::from_packet(&packet, &frame);

    assert_eq!(summary.source, "[2001:db8::1]");
    assert_eq!(summary.destination, "[2001:db8::2]");
}

#[test]
fn summary_brackets_ipv6_with_udp_ports() {
    let packet = Packet::new(
        vec![
            Layer::Ipv6(Ipv6Layer {
                source: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                destination: "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
                next_header: 17, // UDP
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 64,
            }),
            Layer::Udp(UdpLayer {
                source_port: 5353,
                destination_port: 53,
                length: 8,
            }),
        ],
        vec![],
    );
    let frame = Frame::builder().captured_len(62).protocol("UDP").build();
    let summary = PacketSummary::from_packet(&packet, &frame);

    assert_eq!(summary.source, "[2001:db8::1]:5353");
    assert_eq!(summary.destination, "[2001:db8::2]:53");
}
