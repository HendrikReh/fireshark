use fireshark_core::{DecodeIssue, Layer, LayerSpan, Packet, TcpFlags, TcpLayer, UdpLayer};

#[test]
fn packet_can_hold_layers_and_issues() {
    let packet = Packet::new(vec![Layer::Unknown], vec![DecodeIssue::truncated(14)]);

    assert_eq!(packet.layers().len(), 1);
    assert_eq!(packet.issues().len(), 1);
}

#[test]
fn packet_with_spans_stores_and_returns_spans() {
    let packet = Packet::with_spans(
        vec![Layer::Unknown],
        vec![],
        vec![LayerSpan { offset: 0, len: 14 }],
    );
    assert_eq!(packet.spans().len(), 1);
    assert_eq!(packet.spans()[0].offset, 0);
    assert_eq!(packet.spans()[0].len, 14);
}

#[test]
fn packet_new_has_empty_spans() {
    let packet = Packet::new(vec![Layer::Unknown], vec![]);
    assert!(packet.spans().is_empty());
}

#[test]
fn transport_ports_returns_tcp_ports() {
    let packet = Packet::new(
        vec![Layer::Tcp(TcpLayer {
            source_port: 12345,
            destination_port: 443,
            seq: 0,
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
        })],
        vec![],
    );
    assert_eq!(packet.transport_ports(), Some((12345, 443)));
}

#[test]
fn transport_ports_returns_udp_ports() {
    let packet = Packet::new(
        vec![Layer::Udp(UdpLayer {
            source_port: 5353,
            destination_port: 53,
            length: 8,
        })],
        vec![],
    );
    assert_eq!(packet.transport_ports(), Some((5353, 53)));
}

#[test]
fn transport_ports_returns_none_without_transport() {
    let packet = Packet::new(vec![Layer::Unknown], vec![]);
    assert_eq!(packet.transport_ports(), None);
}

#[test]
fn layer_names_returns_ordered_names() {
    let packet = Packet::new(
        vec![
            Layer::Unknown,
            Layer::Udp(UdpLayer {
                source_port: 53,
                destination_port: 5353,
                length: 8,
            }),
        ],
        vec![],
    );
    assert_eq!(packet.layer_names(), vec!["Unknown", "UDP"]);
}
