use fireshark_core::{DecodeIssue, Layer, LayerSpan, Packet};

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
