use std::path::PathBuf;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

#[test]
fn pipeline_decodes_frames_from_reader() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets = Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(packets.len(), 1);
}

fn repo_root() -> PathBuf {
    let mut current = std::env::current_dir().expect("current directory should be available");
    loop {
        if current.join("Cargo.toml").is_file()
            && current.join("crates").is_dir()
            && current.join("fixtures").is_dir()
        {
            return current;
        }

        assert!(current.pop(), "workspace root should exist");
    }
}
