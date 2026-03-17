use std::path::PathBuf;

use fireshark_core::{DecodedFrame, Frame, Packet, Pipeline, PipelineError, TrackingPipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

/// Helper: build a frame from raw bytes.
fn frame_from_bytes(bytes: &[u8]) -> Frame {
    Frame::builder().data(bytes.to_vec()).build()
}

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

#[test]
fn decoded_frame_stream_id_is_none_by_default() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let frame = frame_from_bytes(&tcp_bytes);
    let packet = decode_packet(&tcp_bytes).unwrap();
    let decoded = DecodedFrame::new(frame, packet);

    assert_eq!(decoded.stream_id(), None);
}

#[test]
fn decoded_frame_with_stream_id_sets_id() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let frame = frame_from_bytes(&tcp_bytes);
    let packet = decode_packet(&tcp_bytes).unwrap();
    let decoded = DecodedFrame::new(frame, packet).with_stream_id(Some(42));

    assert_eq!(decoded.stream_id(), Some(42));
}

#[test]
fn plain_pipeline_yields_none_stream_id() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let frames: Vec<Result<Frame, std::convert::Infallible>> =
        vec![Ok(frame_from_bytes(&tcp_bytes))];

    let mut pipeline = Pipeline::new(frames.into_iter(), decode_packet);
    let decoded = pipeline.next().unwrap().unwrap();

    assert_eq!(decoded.stream_id(), None);
}

#[test]
fn tracking_pipeline_assigns_stream_ids_synthetic() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let udp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_udp.bin")).unwrap();
    let arp_bytes = std::fs::read(repo_root().join("fixtures/bytes/ethernet_arp.bin")).unwrap();

    let frames: Vec<Result<Frame, std::convert::Infallible>> = vec![
        Ok(frame_from_bytes(&tcp_bytes)),
        Ok(frame_from_bytes(&udp_bytes)),
        Ok(frame_from_bytes(&tcp_bytes)), // same stream as first
        Ok(frame_from_bytes(&arp_bytes)), // no transport layer
    ];

    let mut pipeline = TrackingPipeline::new(frames.into_iter(), decode_packet);

    let d0 = pipeline.next().unwrap().unwrap();
    assert_eq!(d0.stream_id(), Some(0)); // TCP stream 0

    let d1 = pipeline.next().unwrap().unwrap();
    assert_eq!(d1.stream_id(), Some(1)); // UDP stream 1

    let d2 = pipeline.next().unwrap().unwrap();
    assert_eq!(d2.stream_id(), Some(0)); // same TCP stream

    let d3 = pipeline.next().unwrap().unwrap();
    assert_eq!(d3.stream_id(), None); // ARP, no stream

    assert!(pipeline.next().is_none());
    assert_eq!(pipeline.tracker().stream_count(), 2);
}

#[test]
fn tracking_pipeline_into_tracker_returns_accumulated_data() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();

    let frames: Vec<Result<Frame, std::convert::Infallible>> = vec![
        Ok(frame_from_bytes(&tcp_bytes)),
        Ok(frame_from_bytes(&tcp_bytes)),
    ];

    let pipeline = TrackingPipeline::new(frames.into_iter(), decode_packet);
    let results: Vec<_> = pipeline.collect();
    assert_eq!(results.len(), 2);

    // Re-run to test into_tracker:
    let frames2: Vec<Result<Frame, std::convert::Infallible>> = vec![
        Ok(frame_from_bytes(&tcp_bytes)),
        Ok(frame_from_bytes(&tcp_bytes)),
    ];
    let mut pipeline2 = TrackingPipeline::new(frames2.into_iter(), decode_packet);
    pipeline2.next();
    pipeline2.next();

    let tracker = pipeline2.into_tracker();
    assert_eq!(tracker.stream_count(), 1);
    assert_eq!(tracker.get(0).unwrap().packet_count, 2);
}

#[test]
fn tracking_pipeline_assigns_stream_ids_from_pcap() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = TrackingPipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // minimal.pcap has one TCP packet — it should get a stream_id
    for decoded in &packets {
        if decoded
            .packet()
            .layers()
            .iter()
            .any(|l| matches!(l, fireshark_core::Layer::Tcp(_)))
        {
            assert!(decoded.stream_id().is_some());
        }
    }
}

#[test]
fn default_pipeline_yields_none_stream_id() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    let packets: Vec<_> = Pipeline::new(reader, decode_packet)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Regular Pipeline should always yield None stream_ids
    for decoded in &packets {
        assert_eq!(decoded.stream_id(), None);
    }
}

#[test]
fn tracking_pipeline_error_does_not_corrupt_tracker() {
    let tcp_bytes =
        std::fs::read(repo_root().join("fixtures/bytes/ethernet_ipv4_tcp.bin")).unwrap();

    // Mix Ok and Err frames: Ok, Err, Ok — tracker should handle the
    // successful packets without being affected by the intervening error.
    let frames: Vec<Result<Frame, &str>> = vec![
        Ok(frame_from_bytes(&tcp_bytes)),
        Err("bad frame"),
        Ok(frame_from_bytes(&tcp_bytes)),
    ];

    let mut pipeline = TrackingPipeline::new(frames.into_iter(), decode_packet);

    let d0 = pipeline.next().unwrap();
    assert!(d0.is_ok());
    assert_eq!(d0.unwrap().stream_id(), Some(0));

    let d1 = pipeline.next().unwrap();
    assert!(d1.is_err()); // frame error

    let d2 = pipeline.next().unwrap();
    assert!(d2.is_ok());
    assert_eq!(d2.unwrap().stream_id(), Some(0)); // same stream

    assert!(pipeline.next().is_none());

    let tracker = pipeline.into_tracker();
    assert_eq!(tracker.stream_count(), 1);
    assert_eq!(tracker.get(0).unwrap().packet_count, 2);
}
