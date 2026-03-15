use fireshark_core::{Frame, PacketSummary};

#[test]
fn summary_includes_protocol_and_length() {
    let frame = Frame::builder().captured_len(60).protocol("TCP").build();
    let summary = PacketSummary::from(&frame);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
}
