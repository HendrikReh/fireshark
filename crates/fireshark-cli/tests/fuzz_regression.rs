mod support;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

#[test]
fn fuzz_fixture_does_not_panic() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    for decoded in Pipeline::new(reader, decode_packet) {
        let _ = decoded; // Don't care about errors, just no panics
    }
}
