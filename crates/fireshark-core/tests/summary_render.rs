use std::net::Ipv4Addr;

use fireshark_core::{Ipv4Layer, Layer, Packet, PacketSummary, TcpLayer};

#[test]
fn summary_renders_endpoints_for_tcp_packets() {
    let packet = Packet::new(
        vec![
            Layer::Ipv4(Ipv4Layer {
                source: Ipv4Addr::new(192, 0, 2, 10),
                destination: Ipv4Addr::new(198, 51, 100, 20),
                protocol: 6,
            }),
            Layer::Tcp(TcpLayer {
                source_port: 51514,
                destination_port: 443,
            }),
        ],
        vec![],
    );

    let summary = PacketSummary::from_packet(&packet, 60);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
    assert_eq!(summary.source, "192.0.2.10:51514");
    assert_eq!(summary.destination, "198.51.100.20:443");
}
