mod support;

use fireshark_core::{
    DecodeIssue, DecodedFrame, EthernetLayer, Frame, Ipv4Layer, Layer, Packet, TcpFlags, TcpLayer,
};
use fireshark_mcp::AnalyzedCapture;
use fireshark_mcp::model::LayerView;
use fireshark_mcp::query::{
    MAX_PAGE_SIZE, get_packet, get_stream, list_decode_issues, list_packets, list_streams,
};

#[test]
fn list_packets_returns_packet_summaries() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packets = list_packets(&capture, 0, 10, None, None, None);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
    assert!(packets[0].timestamp.is_some());
    assert!(packets[0].original_len > 0);
}

#[test]
fn get_packet_returns_layers_and_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packet = get_packet(&capture, 0).unwrap();

    assert!(!packet.layers.is_empty());
    assert!(packet.issues.is_empty());
    assert!(packet.timestamp.is_some());
    assert!(packet.original_len > 0);
}

#[test]
fn tcp_layer_view_exposes_new_fields() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packet = get_packet(&capture, 0).unwrap();

    let tcp_layer = packet
        .layers
        .iter()
        .find(|l| matches!(l, LayerView::Tcp { .. }))
        .expect("packet should contain a TCP layer");

    match tcp_layer {
        LayerView::Tcp {
            seq,
            ack,
            data_offset,
            flags,
            window,
            ..
        } => {
            assert_eq!(*seq, 1);
            assert_eq!(*ack, 0);
            assert_eq!(*data_offset, 5);
            assert!(flags.syn);
            assert!(!flags.ack);
            assert_eq!(*window, 1024);
        }
        _ => unreachable!(),
    }
}

#[test]
fn list_packets_clamps_requested_limit() {
    let capture = AnalyzedCapture::from_packets((0..1_010).map(tcp_packet).collect());

    let packets = list_packets(&capture, 0, usize::MAX, None, None, None);

    assert_eq!(packets.len(), MAX_PAGE_SIZE);
}

#[test]
fn list_decode_issues_clamps_requested_limit() {
    let capture = AnalyzedCapture::from_packets((0..1_010).map(|_| malformed_packet()).collect());

    let issues = list_decode_issues(&capture, None, 0, usize::MAX);

    assert_eq!(issues.len(), MAX_PAGE_SIZE);
}

fn tcp_packet(index: usize) -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(
            vec![
                ethernet_layer(),
                Layer::Ipv4(Ipv4Layer {
                    source: std::net::Ipv4Addr::new(10, 0, 0, 1),
                    destination: std::net::Ipv4Addr::new(10, 0, 0, 2),
                    protocol: 6,
                    ttl: 64,
                    identification: index as u16,
                    dscp: 0,
                    ecn: 0,
                    dont_fragment: true,
                    fragment_offset: 0,
                    more_fragments: false,
                    header_checksum: 0,
                }),
                Layer::Tcp(TcpLayer {
                    source_port: 50_000,
                    destination_port: 443,
                    seq: index as u32,
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
            Vec::new(),
        ),
    )
}

fn malformed_packet() -> DecodedFrame {
    DecodedFrame::new(
        frame(),
        Packet::new(
            vec![ethernet_layer(), Layer::Unknown],
            vec![DecodeIssue::malformed(14)],
        ),
    )
}

fn frame() -> Frame {
    Frame::builder()
        .captured_len(64)
        .protocol("UNKNOWN")
        .data(vec![0; 64])
        .build()
        .unwrap()
}

fn ethernet_layer() -> Layer {
    Layer::Ethernet(EthernetLayer {
        destination: [0, 1, 2, 3, 4, 5],
        source: [6, 7, 8, 9, 10, 11],
        ether_type: 0x0800,
    })
}

#[test]
fn list_streams_returns_stream_metadata() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let streams = list_streams(&capture, 0, 100);

    assert!(!streams.is_empty());
    assert_eq!(streams[0].id, 0);
    assert!(!streams[0].protocol.is_empty());
}

#[test]
fn get_stream_returns_packets_for_stream() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let (stream, packets) = get_stream(&capture, 0).expect("stream 0 should exist");

    assert_eq!(stream.id, 0);
    assert!(!packets.is_empty());
}
