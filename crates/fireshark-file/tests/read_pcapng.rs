use fireshark_file::CaptureReader;

mod support;

#[test]
fn reads_single_packet_from_pcapng() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcapng");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(frames.len(), 1);
}

#[test]
fn pcapng_frames_have_timestamps() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcapng");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let frame = &frames[0];
    // Handcrafted fixture has timestamp=0
    assert!(frame.timestamp().is_some());
    assert_eq!(frame.original_len(), 54);
}
