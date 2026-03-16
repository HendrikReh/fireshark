use std::path::PathBuf;

use fireshark_file::CaptureReader;

#[test]
fn reads_single_packet_from_pcap() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcap");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(frames.len(), 1);
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
