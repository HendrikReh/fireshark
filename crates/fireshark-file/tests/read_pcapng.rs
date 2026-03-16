use std::path::PathBuf;

use fireshark_file::CaptureReader;

#[test]
fn reads_single_packet_from_pcapng() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcapng");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(frames.len(), 1);
}

#[test]
fn pcapng_frames_have_timestamps() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcapng");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let frame = &frames[0];
    // Handcrafted fixture has timestamp=0
    assert!(frame.timestamp().is_some());
    assert_eq!(frame.original_len(), 54);
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
