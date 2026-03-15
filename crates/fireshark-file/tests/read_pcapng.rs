use fireshark_file::CaptureReader;

#[test]
fn reads_single_packet_from_pcapng() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/smoke/minimal.pcapng"
    );
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(frames.len(), 1);
}
