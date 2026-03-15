use fireshark_core::{DecodeIssue, Layer, Packet};

#[test]
fn packet_can_hold_layers_and_issues() {
    let packet = Packet::new(vec![Layer::Unknown], vec![DecodeIssue::truncated(14)]);

    assert_eq!(packet.layers().len(), 1);
    assert_eq!(packet.issues().len(), 1);
}
