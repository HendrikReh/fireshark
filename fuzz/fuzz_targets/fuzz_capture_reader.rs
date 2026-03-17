#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else { return };
    if tmp.write_all(data).is_err() { return };
    let path = tmp.path().to_path_buf();
    if let Ok(reader) = fireshark_file::CaptureReader::open(&path) {
        for frame in reader {
            let _ = frame;
        }
    }
});
