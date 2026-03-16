use std::net::Ipv4Addr;
use std::time::Duration;

use fireshark_core::{Frame, Ipv4Layer, Layer, Packet, PacketSummary, TcpFlags, TcpLayer};

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
