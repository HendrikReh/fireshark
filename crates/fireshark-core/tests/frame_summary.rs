use std::time::Duration;

use fireshark_core::{Frame, PacketSummary};

#[test]
fn summary_includes_protocol_and_length() {
    let frame = Frame::builder().captured_len(60).protocol("TCP").build();
    let summary = PacketSummary::from(&frame);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
    assert!(summary.timestamp.is_none());
}

#[test]
fn frame_carries_timestamp_and_original_len() {
    let frame = Frame::builder()
        .captured_len(54)
        .original_len(64)
        .timestamp(Duration::from_secs(1_700_000_000))
        .protocol("TCP")
        .build();

    assert_eq!(frame.timestamp(), Some(Duration::from_secs(1_700_000_000)));
    assert_eq!(frame.original_len(), 64);
    assert_eq!(frame.captured_len(), 54);
}

#[test]
fn original_len_defaults_to_captured_len() {
    let frame = Frame::builder().captured_len(54).protocol("TCP").build();

    assert_eq!(frame.original_len(), 54);
    assert!(frame.timestamp().is_none());
}

#[test]
#[should_panic(expected = "captured_len must match data length")]
fn frame_builder_rejects_mismatched_captured_len() {
    let _ = Frame::builder()
        .captured_len(64)
        .data(vec![0_u8; 60])
        .protocol("TCP")
        .build();
}
