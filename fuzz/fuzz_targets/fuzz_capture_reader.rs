#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(data).unwrap();
    let path = tmp.path().to_path_buf();
    if let Ok(reader) = fireshark_file::CaptureReader::open(&path) {
        for frame in reader {
            let _ = frame;
        }
    }
});
