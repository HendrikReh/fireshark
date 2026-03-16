use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fireshark_file::{CaptureError, CaptureReader};

#[test]
fn rejects_capture_shorter_than_magic_prefix() {
    let path = temp_capture_path();
    fs::write(&path, [0x0a, 0x0d, 0x0d]).unwrap();

    let result = CaptureReader::open(&path);

    fs::remove_file(&path).unwrap();
    assert!(matches!(result, Err(CaptureError::UnsupportedFormat)));
}

fn temp_capture_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fireshark-short-capture-{unique}-{}.pcap",
        std::process::id(),
    ))
}
