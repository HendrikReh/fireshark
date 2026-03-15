use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

#[test]
fn pipeline_decodes_frames_from_reader() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/smoke/minimal.pcap"
    );
    let reader = CaptureReader::open(fixture).unwrap();
    let packets = Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(packets.len(), 1);
}
