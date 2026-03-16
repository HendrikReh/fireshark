use std::path::PathBuf;

use fireshark_core::{Frame, Packet, Pipeline, PipelineError};
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

#[test]
fn pipeline_propagates_frame_errors() {
    let frames: Vec<Result<Frame, &str>> = vec![Err("bad frame")];
    let pipeline = Pipeline::new(frames.into_iter(), |_: &[u8]| -> Result<Packet, &str> {
        panic!("decoder should not be called on frame error");
    });
    let results: Vec<_> = pipeline.collect();
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], Err(PipelineError::Frame("bad frame"))));
}

#[test]
fn pipeline_propagates_decode_errors() {
    let frame = Frame::builder()
        .data(vec![0u8; 14])
        .protocol("test")
        .build();
    let frames: Vec<Result<Frame, &str>> = vec![Ok(frame)];
    let pipeline = Pipeline::new(frames.into_iter(), |_: &[u8]| -> Result<Packet, &str> {
        Err("decode failed")
    });
    let results: Vec<_> = pipeline.collect();
    assert_eq!(results.len(), 1);
    assert!(matches!(
        results[0],
        Err(PipelineError::Decode("decode failed"))
    ));
}

fn repo_root() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut current = manifest_dir.to_path_buf();
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
