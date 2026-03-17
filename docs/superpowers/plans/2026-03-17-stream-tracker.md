# Stream Tracker Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TCP/UDP conversation tracking to fireshark with stream identity, metadata, CLI follow command, MCP stream tools, and filter fields.

**Architecture:** New `StreamTracker` in `fireshark-core` assigns monotonic stream IDs by canonically ordered 5-tuples. `TrackingPipeline` wraps `Pipeline` to assign IDs during iteration. CLI gets `follow` command, MCP gets `list_streams`/`get_stream`/`summarize_capture` tools, filter gets `tcp.stream`/`udp.stream` fields.

**Tech Stack:** Rust, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-17-stream-tracker-design.md`

---

## Chunk 1: Core types (StreamKey, StreamMetadata, StreamTracker)

### Task 1: Create `stream.rs` in fireshark-core

**New file:** `crates/fireshark-core/src/stream.rs`

- [ ] Create the file with `StreamKey`, `StreamMetadata`, `StreamTracker`, and helper extraction functions:

```rust
//! TCP/UDP conversation tracking by canonical 5-tuple.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::{DecodedFrame, Layer};

/// Canonical 5-tuple identifying a bidirectional conversation.
///
/// Both directions normalize to the same key: the "lower" endpoint
/// (by `(addr, port)` lexicographic order) always occupies `addr_lo`/`port_lo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub addr_lo: IpAddr,
    pub port_lo: u16,
    pub addr_hi: IpAddr,
    pub port_hi: u16,
    pub protocol: u8,
}

impl StreamKey {
    /// Create a normalized key from source/destination addresses and ports.
    ///
    /// The lower `(addr, port)` pair is placed first so that both directions
    /// of the same conversation produce the same key.
    pub fn new(
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if (src_addr, src_port) <= (dst_addr, dst_port) {
            Self {
                addr_lo: src_addr,
                port_lo: src_port,
                addr_hi: dst_addr,
                port_hi: dst_port,
                protocol,
            }
        } else {
            Self {
                addr_lo: dst_addr,
                port_lo: dst_port,
                addr_hi: src_addr,
                port_hi: src_port,
                protocol,
            }
        }
    }

    /// Protocol name for display.
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown",
        }
    }
}

/// Per-stream statistics accumulated during iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMetadata {
    pub id: u32,
    pub key: StreamKey,
    pub packet_count: usize,
    pub byte_count: usize,
    pub first_seen: Option<Duration>,
    pub last_seen: Option<Duration>,
}

/// Assigns and tracks stream IDs for TCP/UDP conversations.
///
/// Each unique `StreamKey` receives a monotonically increasing `u32` stream ID
/// starting at 0. Call `assign()` for each decoded frame; packets without a
/// transport layer receive `None`.
#[derive(Debug, Clone)]
pub struct StreamTracker {
    streams: HashMap<StreamKey, u32>,
    metadata: Vec<StreamMetadata>,
    next_id: u32,
}

impl StreamTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            metadata: Vec::new(),
            next_id: 0,
        }
    }

    /// Assign a stream ID to the given decoded frame.
    ///
    /// Returns `None` if the packet has no IP + transport layer pair
    /// (e.g. ARP, ICMP-only, or Ethernet-only).
    pub fn assign(&mut self, decoded: &DecodedFrame) -> Option<u32> {
        let (src_addr, dst_addr) = extract_addresses(decoded.packet().layers())?;
        let (src_port, dst_port, protocol) = extract_transport(decoded.packet().layers())?;
        let key = StreamKey::new(src_addr, src_port, dst_addr, dst_port, protocol);

        let id = if let Some(&id) = self.streams.get(&key) {
            id
        } else {
            let id = self.next_id;
            self.next_id += 1;
            self.streams.insert(key.clone(), id);
            self.metadata.push(StreamMetadata {
                id,
                key,
                packet_count: 0,
                byte_count: 0,
                first_seen: None,
                last_seen: None,
            });
            id
        };

        let meta = &mut self.metadata[id as usize];
        meta.packet_count += 1;
        meta.byte_count += decoded.frame().captured_len();
        let ts = decoded.frame().timestamp();
        if meta.first_seen.is_none() {
            meta.first_seen = ts;
        }
        meta.last_seen = ts;

        Some(id)
    }

    /// All stream metadata in ID order.
    pub fn streams(&self) -> &[StreamMetadata] {
        &self.metadata
    }

    /// Look up metadata for a single stream.
    pub fn get(&self, stream_id: u32) -> Option<&StreamMetadata> {
        self.metadata.get(stream_id as usize)
    }

    /// Number of distinct streams observed.
    pub fn stream_count(&self) -> usize {
        self.metadata.len()
    }
}

impl Default for StreamTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract source and destination IP addresses from the packet layers.
fn extract_addresses(layers: &[Layer]) -> Option<(IpAddr, IpAddr)> {
    for layer in layers {
        match layer {
            Layer::Ipv4(l) => return Some((IpAddr::V4(l.source), IpAddr::V4(l.destination))),
            Layer::Ipv6(l) => return Some((IpAddr::V6(l.source), IpAddr::V6(l.destination))),
            _ => {}
        }
    }
    None
}

/// Extract source port, destination port, and IP protocol number from the transport layer.
fn extract_transport(layers: &[Layer]) -> Option<(u16, u16, u8)> {
    for layer in layers {
        match layer {
            Layer::Tcp(l) => return Some((l.source_port, l.destination_port, 6)),
            Layer::Udp(l) => return Some((l.source_port, l.destination_port, 17)),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{Frame, Packet};
    use fireshark_dissectors::decode_packet;

    // --- StreamKey normalization tests ---

    #[test]
    fn stream_key_normalizes_direction() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let forward = StreamKey::new(a, 80, b, 12345, 6);
        let reverse = StreamKey::new(b, 12345, a, 80, 6);

        assert_eq!(forward, reverse);
    }

    #[test]
    fn stream_key_same_addr_different_ports_normalizes() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let forward = StreamKey::new(addr, 1000, addr, 2000, 6);
        let reverse = StreamKey::new(addr, 2000, addr, 1000, 6);

        assert_eq!(forward, reverse);
        assert_eq!(forward.port_lo, 1000);
        assert_eq!(forward.port_hi, 2000);
    }

    #[test]
    fn stream_key_different_protocols_differ() {
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let tcp = StreamKey::new(a, 80, b, 12345, 6);
        let udp = StreamKey::new(a, 80, b, 12345, 17);

        assert_ne!(tcp, udp);
    }

    #[test]
    fn stream_key_ipv6_normalizes() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let forward = StreamKey::new(a, 443, b, 51234, 6);
        let reverse = StreamKey::new(b, 51234, a, 443, 6);

        assert_eq!(forward, reverse);
    }

    #[test]
    fn stream_key_protocol_name() {
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        assert_eq!(StreamKey::new(a, 80, b, 1234, 6).protocol_name(), "TCP");
        assert_eq!(StreamKey::new(a, 53, b, 1234, 17).protocol_name(), "UDP");
        assert_eq!(StreamKey::new(a, 80, b, 1234, 1).protocol_name(), "Unknown");
    }

    // --- StreamTracker tests ---

    /// Helper: build a DecodedFrame from raw ethernet bytes.
    fn decoded_from_bytes(bytes: &[u8]) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build();
        DecodedFrame::new(frame, packet)
    }

    /// Helper: build a DecodedFrame from raw bytes with a timestamp.
    fn decoded_from_bytes_ts(bytes: &[u8], ts: Duration) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder()
            .data(bytes.to_vec())
            .timestamp(ts)
            .build();
        DecodedFrame::new(frame, packet)
    }

    #[test]
    fn stream_tracker_assigns_same_id_for_both_directions() {
        // Both TCP fixture packets use the same 5-tuple in one direction,
        // but StreamKey normalizes so the same ID should be returned.
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let decoded = decoded_from_bytes(tcp_bytes);

        let mut tracker = StreamTracker::new();
        let id1 = tracker.assign(&decoded);
        let id2 = tracker.assign(&decoded);

        assert_eq!(id1, Some(0));
        assert_eq!(id2, Some(0));
        assert_eq!(tracker.stream_count(), 1);
    }

    #[test]
    fn stream_tracker_assigns_different_ids_for_different_streams() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let udp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_udp.bin");

        let tcp_decoded = decoded_from_bytes(tcp_bytes);
        let udp_decoded = decoded_from_bytes(udp_bytes);

        let mut tracker = StreamTracker::new();
        let tcp_id = tracker.assign(&tcp_decoded);
        let udp_id = tracker.assign(&udp_decoded);

        assert_eq!(tcp_id, Some(0));
        assert_eq!(udp_id, Some(1));
        assert_eq!(tracker.stream_count(), 2);
    }

    #[test]
    fn stream_tracker_returns_none_for_non_transport_packets() {
        let arp_bytes = include_bytes!("../../fixtures/bytes/ethernet_arp.bin");
        let decoded = decoded_from_bytes(arp_bytes);

        let mut tracker = StreamTracker::new();
        let id = tracker.assign(&decoded);

        assert_eq!(id, None);
        assert_eq!(tracker.stream_count(), 0);
    }

    #[test]
    fn stream_metadata_tracks_packet_count_and_bytes() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let decoded = decoded_from_bytes(tcp_bytes);

        let mut tracker = StreamTracker::new();
        tracker.assign(&decoded);
        tracker.assign(&decoded);
        tracker.assign(&decoded);

        let meta = tracker.get(0).unwrap();
        assert_eq!(meta.packet_count, 3);
        assert_eq!(meta.byte_count, tcp_bytes.len() * 3);
    }

    #[test]
    fn stream_metadata_tracks_timestamps() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");

        let ts1 = Duration::from_millis(1000);
        let ts2 = Duration::from_millis(2000);
        let ts3 = Duration::from_millis(3000);

        let d1 = decoded_from_bytes_ts(tcp_bytes, ts1);
        let d2 = decoded_from_bytes_ts(tcp_bytes, ts2);
        let d3 = decoded_from_bytes_ts(tcp_bytes, ts3);

        let mut tracker = StreamTracker::new();
        tracker.assign(&d1);
        tracker.assign(&d2);
        tracker.assign(&d3);

        let meta = tracker.get(0).unwrap();
        assert_eq!(meta.first_seen, Some(ts1));
        assert_eq!(meta.last_seen, Some(ts3));
    }

    #[test]
    fn stream_tracker_get_returns_none_for_invalid_id() {
        let tracker = StreamTracker::new();
        assert!(tracker.get(0).is_none());
        assert!(tracker.get(999).is_none());
    }

    #[test]
    fn stream_tracker_default_is_empty() {
        let tracker = StreamTracker::default();
        assert_eq!(tracker.stream_count(), 0);
        assert!(tracker.streams().is_empty());
    }
}
```

- [ ] Run `just check` to verify everything compiles and tests pass.
- [ ] Commit: `add: StreamKey, StreamMetadata, StreamTracker in fireshark-core`

---

## Chunk 2: Pipeline integration (DecodedFrame + TrackingPipeline)

### Task 2: Add `stream_id` field to DecodedFrame

**File:** `crates/fireshark-core/src/pipeline.rs`

- [ ] Add `stream_id: Option<u32>` field to `DecodedFrame`:

```rust
/// A successfully decoded frame paired with its packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    frame: Frame,
    packet: Packet,
    stream_id: Option<u32>,
}
```

- [ ] Update `DecodedFrame::new()` to initialize `stream_id: None`:

```rust
impl DecodedFrame {
    /// Wrap a frame and its decoded packet.
    pub fn new(frame: Frame, packet: Packet) -> Self {
        Self {
            frame,
            packet,
            stream_id: None,
        }
    }
```

- [ ] Add `stream_id()` accessor and `with_stream_id()` builder:

```rust
    /// Stream ID assigned by a [`TrackingPipeline`], if available.
    pub fn stream_id(&self) -> Option<u32> {
        self.stream_id
    }

    /// Return a new frame with the given stream ID set.
    pub fn with_stream_id(mut self, id: Option<u32>) -> Self {
        self.stream_id = id;
        self
    }
```

### Task 3: Add TrackingPipeline to pipeline.rs

**File:** `crates/fireshark-core/src/pipeline.rs`

- [ ] Add `use crate::stream::StreamTracker;` to the imports at the top of the file.

- [ ] Add `TrackingPipeline` struct and `Iterator` impl after the existing `Pipeline` impl:

```rust
/// A [`Pipeline`] wrapper that assigns stream IDs via a [`StreamTracker`].
///
/// Each successfully decoded frame is passed through the tracker, which
/// extracts the 5-tuple and assigns (or looks up) a monotonic stream ID.
/// The ID is set on the [`DecodedFrame`] via [`DecodedFrame::with_stream_id`].
pub struct TrackingPipeline<I, D> {
    inner: Pipeline<I, D>,
    tracker: StreamTracker,
}

impl<I, D> TrackingPipeline<I, D> {
    /// Create a tracking pipeline from a frame iterator and decoder function.
    pub fn new(frames: I, decoder: D) -> Self {
        Self {
            inner: Pipeline::new(frames, decoder),
            tracker: StreamTracker::new(),
        }
    }

    /// Borrow the accumulated stream tracker.
    pub fn tracker(&self) -> &StreamTracker {
        &self.tracker
    }

    /// Consume the pipeline and return the stream tracker with all metadata.
    pub fn into_tracker(self) -> StreamTracker {
        self.tracker
    }
}

impl<I, D, FrameError, DecodeError> Iterator for TrackingPipeline<I, D>
where
    I: Iterator<Item = Result<Frame, FrameError>>,
    D: Fn(&[u8]) -> Result<Packet, DecodeError>,
{
    type Item = Result<DecodedFrame, PipelineError<FrameError, DecodeError>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.inner.next()?;
        Some(result.map(|decoded| {
            let stream_id = self.tracker.assign(&decoded);
            decoded.with_stream_id(stream_id)
        }))
    }
}
```

### Task 4: Unit tests for pipeline changes

**File:** `crates/fireshark-core/src/pipeline.rs` (append to file, or add `#[cfg(test)] mod tests`)

Note: `pipeline.rs` currently has no test module. Add one. The tests need to construct a `Pipeline` and `TrackingPipeline` from synthetic frame iterators.

- [ ] Add test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;
    use fireshark_dissectors::decode_packet;

    /// Helper: build frames from raw bytes.
    fn frame_from_bytes(bytes: &[u8]) -> Frame {
        Frame::builder().data(bytes.to_vec()).build()
    }

    #[test]
    fn decoded_frame_stream_id_is_none_by_default() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let frame = frame_from_bytes(tcp_bytes);
        let packet = decode_packet(tcp_bytes).unwrap();
        let decoded = DecodedFrame::new(frame, packet);

        assert_eq!(decoded.stream_id(), None);
    }

    #[test]
    fn decoded_frame_with_stream_id_sets_id() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let frame = frame_from_bytes(tcp_bytes);
        let packet = decode_packet(tcp_bytes).unwrap();
        let decoded = DecodedFrame::new(frame, packet).with_stream_id(Some(42));

        assert_eq!(decoded.stream_id(), Some(42));
    }

    #[test]
    fn plain_pipeline_yields_none_stream_id() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let frames = vec![Ok(frame_from_bytes(tcp_bytes))];

        let mut pipeline = Pipeline::new(frames.into_iter(), decode_packet);
        let decoded = pipeline.next().unwrap().unwrap();

        assert_eq!(decoded.stream_id(), None);
    }

    #[test]
    fn tracking_pipeline_assigns_stream_ids() {
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let udp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_udp.bin");
        let arp_bytes = include_bytes!("../../fixtures/bytes/ethernet_arp.bin");

        let frames: Vec<Result<Frame, std::convert::Infallible>> = vec![
            Ok(frame_from_bytes(tcp_bytes)),
            Ok(frame_from_bytes(udp_bytes)),
            Ok(frame_from_bytes(tcp_bytes)), // same stream as first
            Ok(frame_from_bytes(arp_bytes)), // no transport layer
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
        let tcp_bytes = include_bytes!("../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let frames: Vec<Result<Frame, std::convert::Infallible>> =
            vec![Ok(frame_from_bytes(tcp_bytes)), Ok(frame_from_bytes(tcp_bytes))];

        let pipeline = TrackingPipeline::new(frames.into_iter(), decode_packet);
        // Consume the entire pipeline
        let results: Vec<_> = pipeline.collect();
        // Can't call into_tracker after collect() since pipeline is consumed.
        // Instead, use tracker() before consuming:
        assert_eq!(results.len(), 2);

        // Re-run to test into_tracker:
        let frames2: Vec<Result<Frame, std::convert::Infallible>> =
            vec![Ok(frame_from_bytes(tcp_bytes)), Ok(frame_from_bytes(tcp_bytes))];
        let mut pipeline2 = TrackingPipeline::new(frames2.into_iter(), decode_packet);
        pipeline2.next();
        pipeline2.next();

        let tracker = pipeline2.into_tracker();
        assert_eq!(tracker.stream_count(), 1);
        assert_eq!(tracker.get(0).unwrap().packet_count, 2);
    }
}
```

### Task 5: Export new types from lib.rs

**File:** `crates/fireshark-core/src/lib.rs`

- [ ] Add `mod stream;` to the module list:

```rust
mod frame;
mod issues;
mod layer;
mod packet;
mod pipeline;
mod stream;
mod summary;
```

- [ ] Add stream types and `TrackingPipeline` to the `pub use` exports:

```rust
pub use pipeline::{DecodedFrame, Pipeline, PipelineError, TrackingPipeline};
pub use stream::{StreamKey, StreamMetadata, StreamTracker};
```

- [ ] Run `just check` to verify everything compiles and tests pass.
- [ ] Commit: `add: TrackingPipeline and stream_id on DecodedFrame`

---

## Chunk 3: Filter integration

### Task 6: Add `tcp.stream` and `udp.stream` fields to evaluate.rs

**File:** `crates/fireshark-filter/src/evaluate.rs`

- [ ] Add `tcp.stream` and `udp.stream` handling to `resolve_field()`.

These fields resolve from `DecodedFrame::stream_id()`, not from any layer. They must be checked **before** the fallback to `resolve_layer_field`, alongside the existing `frame.len` and `frame.cap_len` fields. The field only resolves when the matching transport layer is present.

Update the `resolve_field` function:

```rust
fn resolve_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    match field {
        "frame.len" => Some(FieldValue::Integer(decoded.frame().original_len() as u64)),
        "frame.cap_len" => Some(FieldValue::Integer(decoded.frame().captured_len() as u64)),
        "tcp.stream" => {
            if decoded
                .packet()
                .layers()
                .iter()
                .any(|l| matches!(l, Layer::Tcp(_)))
            {
                decoded
                    .stream_id()
                    .map(|id| FieldValue::Integer(u64::from(id)))
            } else {
                None
            }
        }
        "udp.stream" => {
            if decoded
                .packet()
                .layers()
                .iter()
                .any(|l| matches!(l, Layer::Udp(_)))
            {
                decoded
                    .stream_id()
                    .map(|id| FieldValue::Integer(u64::from(id)))
            } else {
                None
            }
        }
        _ => resolve_layer_field(field, decoded),
    }
}
```

### Task 7: Tests for tcp.stream and udp.stream filter fields

**File:** `crates/fireshark-filter/src/evaluate.rs` (append to existing `mod tests`)

The stream filter fields depend on `DecodedFrame::stream_id()` being set, which only happens when using `TrackingPipeline`. For unit tests, we need to use `with_stream_id()` to set the ID manually.

- [ ] Add a new helper and tests:

```rust
    /// Helper: build a DecodedFrame from raw bytes with a stream ID.
    fn decoded_from_bytes_with_stream(bytes: &[u8], stream_id: Option<u32>) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build();
        DecodedFrame::new(frame, packet).with_stream_id(stream_id)
    }

    // --- tcp.stream / udp.stream filter fields ---

    #[test]
    fn tcp_stream_matches_when_set() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            Some(5),
        );
        assert!(run_filter("tcp.stream == 5", &decoded));
        assert!(!run_filter("tcp.stream == 3", &decoded));
    }

    #[test]
    fn tcp_stream_bare_field_true_when_set() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            Some(0),
        );
        assert!(run_filter("tcp.stream", &decoded));
    }

    #[test]
    fn tcp_stream_bare_field_false_when_not_set() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("tcp.stream", &decoded));
    }

    #[test]
    fn tcp_stream_not_present_on_udp_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin"),
            Some(5),
        );
        assert!(!run_filter("tcp.stream == 5", &decoded));
    }

    #[test]
    fn udp_stream_matches_when_set() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin"),
            Some(3),
        );
        assert!(run_filter("udp.stream == 3", &decoded));
        assert!(!run_filter("udp.stream == 0", &decoded));
    }

    #[test]
    fn udp_stream_bare_field_true_when_set() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin"),
            Some(0),
        );
        assert!(run_filter("udp.stream", &decoded));
    }

    #[test]
    fn udp_stream_not_present_on_tcp_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            Some(5),
        );
        assert!(!run_filter("udp.stream == 5", &decoded));
    }

    #[test]
    fn stream_field_returns_none_for_non_transport_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_arp.bin"),
            None,
        );
        assert!(!run_filter("tcp.stream", &decoded));
        assert!(!run_filter("udp.stream", &decoded));
    }
```

- [ ] Run `just check` to verify everything compiles and tests pass.
- [ ] Commit: `add: tcp.stream and udp.stream filter fields`

---

## Chunk 4: CLI integration (follow + stats update)

### Task 8: Create follow command

**New file:** `crates/fireshark-cli/src/follow.rs`

- [ ] Create the follow command module:

```rust
//! Follow a single TCP/UDP stream by ID.

use std::path::Path;

use fireshark_core::{DecodedFrame, TrackingPipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

pub fn run(path: &Path, stream_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    let mut packets: Vec<(usize, DecodedFrame)> = Vec::new();

    let mut pipeline = TrackingPipeline::new(reader, decode_packet);
    let mut index: usize = 0;

    for result in &mut pipeline {
        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", index + 1);
                index += 1;
                continue;
            }
        };

        if decoded.stream_id() == Some(stream_id) {
            packets.push((index, decoded));
        }

        index += 1;
    }

    let tracker = pipeline.into_tracker();

    let meta = match tracker.get(stream_id) {
        Some(m) => m,
        None => {
            eprintln!("error: stream {stream_id} not found (capture has {} streams)", tracker.stream_count());
            std::process::exit(1);
        }
    };

    // Print stream header
    println!(
        "Stream {} ({})  {} <-> {}",
        meta.id,
        meta.key.protocol_name(),
        format_endpoint(meta.key.addr_lo, meta.key.port_lo),
        format_endpoint(meta.key.addr_hi, meta.key.port_hi),
    );

    let duration_str = match (meta.first_seen, meta.last_seen) {
        (Some(first), Some(last)) => {
            let dur = last.saturating_sub(first);
            format_duration(dur)
        }
        _ => String::from("-"),
    };

    println!(
        "Packets: {}  Bytes: {}  Duration: {}",
        meta.packet_count, meta.byte_count, duration_str
    );
    println!("{}", "\u{2500}".repeat(78));

    // Print each packet in the stream
    for (pkt_index, decoded) in &packets {
        let summary = decoded.summary();
        let ts = match summary.timestamp {
            Some(duration) => timestamp::format_utc(duration),
            None => String::from("-"),
        };
        let line = format!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            pkt_index + 1,
            ts,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}

fn format_endpoint(addr: std::net::IpAddr, port: u16) -> String {
    match addr {
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let total_ms = duration.as_millis();
    if total_ms < 1000 {
        format!("{total_ms}ms")
    } else {
        let secs = duration.as_secs();
        let ms = duration.subsec_millis();
        format!("{secs}.{ms:03}s")
    }
}
```

### Task 9: Update stats.rs to use TrackingPipeline and show stream count

**File:** `crates/fireshark-cli/src/stats.rs`

- [ ] Change the `Pipeline` import to `TrackingPipeline`:

Replace:
```rust
use fireshark_core::Pipeline;
```

With:
```rust
use fireshark_core::TrackingPipeline;
```

- [ ] Change the pipeline construction and iteration to use `TrackingPipeline`:

Replace:
```rust
    for result in Pipeline::new(reader, decode_packet) {
```

With:
```rust
    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    for result in &mut pipeline {
```

- [ ] After the iteration loop, extract the tracker and print stream stats.

Insert after the loop ends (before `println!("Capture Statistics")`):

```rust
    let tracker = pipeline.into_tracker();

    let tcp_stream_count = tracker
        .streams()
        .iter()
        .filter(|m| m.key.protocol == 6)
        .count();
    let udp_stream_count = tracker
        .streams()
        .iter()
        .filter(|m| m.key.protocol == 17)
        .count();
    let total_streams = tracker.stream_count();
```

- [ ] Add stream count to the output, after the "Packets:" line and before the "Duration:" line.

Insert after the `println!("Packets:    {packet_count}");` line:

```rust
    println!(
        "Streams:    {total_streams}  ({tcp_stream_count} TCP, {udp_stream_count} UDP)"
    );
```

The complete updated `stats.rs` should look like:

```rust
//! Capture statistics: packet count, duration, protocol distribution, top endpoints.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use fireshark_core::TrackingPipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::timestamp;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;

    let mut packet_count: usize = 0;
    let mut first_ts: Option<Duration> = None;
    let mut last_ts: Option<Duration> = None;
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoint_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    for result in &mut pipeline {
        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", packet_count + 1);
                packet_count += 1;
                continue;
            }
        };

        packet_count += 1;

        if let Some(ts) = decoded.frame().timestamp() {
            if first_ts.is_none() || Some(ts) < first_ts {
                first_ts = Some(ts);
            }
            if last_ts.is_none() || Some(ts) > last_ts {
                last_ts = Some(ts);
            }
        }

        let summary = decoded.summary();
        *protocol_counts.entry(summary.protocol).or_insert(0) += 1;

        for endpoint in [summary.source, summary.destination] {
            if endpoint.is_empty() {
                continue;
            }
            *endpoint_counts.entry(endpoint).or_insert(0) += 1;
        }
    }

    let tracker = pipeline.into_tracker();
    let tcp_stream_count = tracker
        .streams()
        .iter()
        .filter(|m| m.key.protocol == 6)
        .count();
    let udp_stream_count = tracker
        .streams()
        .iter()
        .filter(|m| m.key.protocol == 17)
        .count();
    let total_streams = tracker.stream_count();

    println!("Capture Statistics");
    println!("{}", "\u{2500}".repeat(38));

    println!("Packets:    {packet_count}");
    println!("Streams:    {total_streams}  ({tcp_stream_count} TCP, {udp_stream_count} UDP)");

    match (first_ts, last_ts) {
        (Some(first), Some(last)) => {
            let duration = last.saturating_sub(first);
            println!(
                "Duration:   {} ({} \u{2192} {})",
                format_duration(duration),
                timestamp::format_utc(first),
                timestamp::format_utc(last)
            );
        }
        _ => {
            println!("Duration:   -");
        }
    }

    println!();
    println!("Protocol Distribution:");

    let mut protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
    protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (protocol, count) in &protocols {
        let pct = if packet_count > 0 {
            (*count as f64 / packet_count as f64) * 100.0
        } else {
            0.0
        };
        println!("  {protocol:<10} {count:>4}  ({pct:>4.1}%)");
    }

    println!();
    println!("Top Endpoints (10):");

    let mut endpoints: Vec<(String, usize)> = endpoint_counts.into_iter().collect();
    endpoints.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    endpoints.truncate(10);

    for (endpoint, count) in &endpoints {
        println!("  {endpoint:<22} {count:>4} packets");
    }

    Ok(())
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{total_secs}s")
    }
}
```

### Task 10: Wire follow command into main.rs

**File:** `crates/fireshark-cli/src/main.rs`

- [ ] Add `mod follow;` to the module list:

```rust
mod audit;
mod color;
mod detail;
mod follow;
mod hexdump;
mod issues;
mod stats;
mod summary;
mod timestamp;
```

- [ ] Add the `Follow` variant to the `Command` enum:

```rust
#[derive(Debug, Subcommand)]
enum Command {
    Summary {
        path: PathBuf,
        #[arg(short = 'f', long = "filter", help = "Display filter expression")]
        filter: Option<String>,
    },
    Detail {
        path: PathBuf,
        #[arg(help = "Packet number (1-indexed)")]
        packet: usize,
    },
    Stats {
        path: PathBuf,
    },
    Issues {
        path: PathBuf,
    },
    Audit {
        path: PathBuf,
    },
    Follow {
        path: PathBuf,
        #[arg(help = "Stream ID (0-indexed)")]
        stream_id: u32,
    },
}
```

- [ ] Add the follow match arm in `main()`:

```rust
    match cli.command {
        Command::Summary { path, filter } => summary::run(&path, filter.as_deref())?,
        Command::Detail { path, packet } => detail::run(&path, packet)?,
        Command::Stats { path } => stats::run(&path)?,
        Command::Issues { path } => issues::run(&path)?,
        Command::Audit { path } => audit::run(&path)?,
        Command::Follow { path, stream_id } => follow::run(&path, stream_id)?,
    }
```

### Task 11: Integration tests for CLI

**File:** `crates/fireshark-cli/tests/` (existing integration test files, or create new)

Check where CLI integration tests live:

- [ ] Add follow command test (success case, using a pcap with TCP packets):

```rust
#[test]
fn follow_command_shows_stream_packets() {
    Command::cargo_bin("fireshark")
        .unwrap()
        .arg("follow")
        .arg("../../fixtures/smoke/http.pcap") // adjust to existing fixture with TCP traffic
        .arg("0")
        .assert()
        .success()
        .stdout(predicates::str::contains("Stream 0"));
}
```

- [ ] Add follow command test (failure case, non-existent stream ID):

```rust
#[test]
fn follow_command_fails_for_invalid_stream_id() {
    Command::cargo_bin("fireshark")
        .unwrap()
        .arg("follow")
        .arg("../../fixtures/smoke/http.pcap") // adjust to existing fixture
        .arg("99999")
        .assert()
        .failure()
        .stderr(predicates::str::contains("not found"));
}
```

- [ ] Add stats command test that verifies stream count appears:

```rust
#[test]
fn stats_command_shows_stream_count() {
    Command::cargo_bin("fireshark")
        .unwrap()
        .arg("stats")
        .arg("../../fixtures/smoke/http.pcap") // adjust to existing fixture
        .assert()
        .success()
        .stdout(predicates::str::contains("Streams:"));
}
```

**Note:** Check which pcap fixtures exist in `fixtures/smoke/` and use the appropriate one. If only `*.pcap` files with TCP traffic exist, use those. If the fixture paths differ, adjust accordingly.

- [ ] Run `just check` to verify everything compiles and tests pass.
- [ ] Commit: `add: CLI follow command and stream count in stats`

---

## Chunk 5: MCP integration (list_streams, get_stream, summarize_capture)

### Task 12: Update AnalyzedCapture to use TrackingPipeline

**File:** `crates/fireshark-mcp/src/analysis.rs`

- [ ] Change import from `Pipeline` to `TrackingPipeline`:

Replace:
```rust
use fireshark_core::{DecodedFrame, Pipeline, PipelineError};
```

With:
```rust
use fireshark_core::{DecodedFrame, PipelineError, StreamTracker, TrackingPipeline};
```

- [ ] Add `tracker: StreamTracker` field to `AnalyzedCapture`:

```rust
#[derive(Debug, Clone)]
pub struct AnalyzedCapture {
    packets: Vec<DecodedFrame>,
    protocol_counts: BTreeMap<String, usize>,
    endpoint_counts: BTreeMap<String, usize>,
    tracker: StreamTracker,
}
```

- [ ] Update `open_with_limit` to use `TrackingPipeline`:

```rust
    pub fn open_with_limit(
        path: impl AsRef<Path>,
        max_packets: usize,
    ) -> Result<Self, AnalysisError> {
        let reader = CaptureReader::open(path)?;
        let mut packets = Vec::new();
        let mut pipeline = TrackingPipeline::new(reader, decode_packet);
        for result in &mut pipeline {
            let frame = result.map_err(AnalysisError::from)?;
            packets.push(frame);
            if packets.len() > max_packets {
                return Err(AnalysisError::TooLarge { max_packets });
            }
        }
        let tracker = pipeline.into_tracker();

        Ok(Self::from_packets_with_tracker(packets, tracker))
    }
```

- [ ] Add `from_packets_with_tracker` and update `from_packets`:

```rust
    pub fn from_packets(packets: Vec<DecodedFrame>) -> Self {
        Self::from_packets_with_tracker(packets, StreamTracker::default())
    }

    pub fn from_packets_with_tracker(
        packets: Vec<DecodedFrame>,
        tracker: StreamTracker,
    ) -> Self {
        let mut protocol_counts = BTreeMap::new();
        let mut endpoint_counts = BTreeMap::new();

        for packet in &packets {
            let summary = packet.summary();
            *protocol_counts.entry(summary.protocol).or_insert(0) += 1;

            for endpoint in [summary.source, summary.destination] {
                if endpoint.is_empty() {
                    continue;
                }

                *endpoint_counts.entry(endpoint).or_insert(0) += 1;
            }
        }

        Self {
            packets,
            protocol_counts,
            endpoint_counts,
            tracker,
        }
    }
```

- [ ] Add stream accessors:

```rust
    /// All stream metadata in ID order.
    pub fn streams(&self) -> &[fireshark_core::StreamMetadata] {
        self.tracker.streams()
    }

    /// The underlying stream tracker.
    pub fn tracker(&self) -> &StreamTracker {
        &self.tracker
    }

    /// Return all packets belonging to a given stream, with their indices.
    pub fn stream_packets(&self, stream_id: u32) -> Vec<(usize, &DecodedFrame)> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, pkt)| pkt.stream_id() == Some(stream_id))
            .collect()
    }
```

### Task 13: Add StreamView and CaptureSummaryView to model.rs

**File:** `crates/fireshark-mcp/src/model.rs`

- [ ] Add `StreamView` after `EndpointCountView`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamView {
    pub id: u32,
    pub protocol: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub packet_count: usize,
    pub byte_count: usize,
    pub duration_ms: Option<u64>,
}
```

- [ ] Add `StreamListResponse`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamListResponse {
    pub streams: Vec<StreamView>,
}
```

- [ ] Add `StreamPacketsResponse`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamPacketsResponse {
    pub stream: StreamView,
    pub packets: Vec<PacketSummaryView>,
}
```

- [ ] Add `CaptureSummaryView`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CaptureSummaryView {
    pub packet_count: usize,
    pub stream_count: usize,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub duration_ms: Option<u64>,
    pub protocols: Vec<ProtocolCountView>,
    pub top_endpoints: Vec<EndpointCountView>,
    pub finding_count: usize,
}
```

- [ ] Add helper `impl StreamView`:

```rust
impl StreamView {
    pub fn from_metadata(meta: &fireshark_core::StreamMetadata) -> Self {
        let duration_ms = match (meta.first_seen, meta.last_seen) {
            (Some(first), Some(last)) => {
                Some(last.saturating_sub(first).as_millis() as u64)
            }
            _ => None,
        };

        Self {
            id: meta.id,
            protocol: meta.key.protocol_name().to_string(),
            endpoint_a: format_stream_endpoint(meta.key.addr_lo, meta.key.port_lo),
            endpoint_b: format_stream_endpoint(meta.key.addr_hi, meta.key.port_hi),
            packet_count: meta.packet_count,
            byte_count: meta.byte_count,
            duration_ms,
        }
    }
}

fn format_stream_endpoint(addr: std::net::IpAddr, port: u16) -> String {
    match addr {
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
    }
}
```

### Task 14: Add stream query functions to query.rs

**File:** `crates/fireshark-mcp/src/query.rs`

- [ ] Add `list_streams` function:

```rust
pub fn list_streams(
    capture: &AnalyzedCapture,
    offset: usize,
    limit: usize,
) -> Vec<StreamView> {
    let limit = clamp_limit(limit);

    capture
        .streams()
        .iter()
        .skip(offset)
        .take(limit)
        .map(StreamView::from_metadata)
        .collect()
}
```

- [ ] Add `get_stream` function:

```rust
pub fn get_stream(
    capture: &AnalyzedCapture,
    stream_id: u32,
) -> Option<(StreamView, Vec<PacketSummaryView>)> {
    let meta = capture.tracker().get(stream_id)?;
    let stream_view = StreamView::from_metadata(meta);
    let packets = capture
        .stream_packets(stream_id)
        .into_iter()
        .map(|(index, pkt)| PacketSummaryView::from_frame(index, pkt))
        .collect();
    Some((stream_view, packets))
}
```

- [ ] Add the necessary import for `StreamView` at the top:

```rust
use crate::model::{
    DecodeIssueEntryView, DecodeIssueView, EndpointCountView, LayerView, PacketDetailView,
    PacketSummaryView, ProtocolCountView, StreamView, format_issue_kind,
};
```

### Task 15: Add list_streams, get_stream, summarize_capture tools to server.rs + tools.rs

**File:** `crates/fireshark-mcp/src/tools.rs`

- [ ] Add stream-not-found variant to `ToolError`:

```rust
#[derive(Debug, Error)]
pub enum ToolError {
    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("packet {index} was not found in session {session_id}")]
    PacketNotFound { session_id: String, index: usize },

    #[error("finding {finding_id} was not found in session {session_id}")]
    FindingNotFound {
        session_id: String,
        finding_id: String,
    },

    #[error("stream {stream_id} was not found in session {session_id}")]
    StreamNotFound {
        session_id: String,
        stream_id: u32,
    },
}
```

- [ ] Add `list_streams` method to `ToolService`:

```rust
    pub async fn list_streams(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StreamView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(list_streams(&session.capture, offset, limit))
    }
```

- [ ] Add `get_stream` method to `ToolService`:

```rust
    pub async fn get_stream(
        &self,
        session_id: &str,
        stream_id: u32,
    ) -> Result<(StreamView, Vec<PacketSummaryView>), ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        get_stream(&session.capture, stream_id).ok_or_else(|| ToolError::StreamNotFound {
            session_id: session_id.to_string(),
            stream_id,
        })
    }
```

- [ ] Add `summarize_capture` method to `ToolService`:

```rust
    pub async fn summarize_capture(
        &self,
        session_id: &str,
    ) -> Result<CaptureSummaryView, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        let protocols = summarize_protocols(&session.capture);
        let top_eps = top_endpoints(&session.capture, 10);

        let all_timestamps: Vec<_> = session
            .capture
            .packets()
            .iter()
            .filter_map(|p| p.frame().timestamp())
            .collect();

        let first_timestamp = all_timestamps.first().copied();
        let last_timestamp = all_timestamps.last().copied();

        let duration_ms = match (first_timestamp, last_timestamp) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_millis() as u64),
            _ => None,
        };

        let finding_count = session.findings().len();

        Ok(CaptureSummaryView {
            packet_count: session.capture.packet_count(),
            stream_count: session.capture.tracker().stream_count(),
            first_timestamp: first_timestamp.map(format_timestamp_utc),
            last_timestamp: last_timestamp.map(format_timestamp_utc),
            duration_ms,
            protocols,
            top_endpoints: top_eps,
            finding_count,
        })
    }
```

- [ ] Add the necessary imports to `tools.rs`:

Add to the `crate::model` import:

```rust
use crate::model::{
    CaptureDescriptionView, CaptureSummaryView, CloseCaptureResponse, DecodeIssueEntryView,
    EndpointCountView, FindingView, OpenCaptureResponse, PacketDetailView, PacketSummaryView,
    ProtocolCountView, StreamView,
};
```

Add to the `crate::query` import:

```rust
use crate::query::{
    PacketSearch, get_packet, get_stream, list_decode_issues, list_packets, list_streams,
    search_packets, summarize_protocols, top_endpoints,
};
```

- [ ] Add `format_timestamp_utc` helper to `tools.rs` (or reuse from query.rs).

Since `query.rs` already has `format_timestamp` as a private function, either make it `pub(crate)` or add a similar function to `tools.rs`:

In `crates/fireshark-mcp/src/query.rs`, change:

```rust
fn format_timestamp(duration: std::time::Duration) -> String {
```

to:

```rust
pub(crate) fn format_timestamp(duration: std::time::Duration) -> String {
```

Then in `tools.rs`, import and use it:

```rust
use crate::query::format_timestamp;
```

And rename the usage to `format_timestamp` instead of `format_timestamp_utc`:

```rust
            first_timestamp: first_timestamp.map(format_timestamp),
            last_timestamp: last_timestamp.map(format_timestamp),
```

Also expose `civil_from_days` if needed (it's a dependency of `format_timestamp`). Since `civil_from_days` is called inside `format_timestamp`, it doesn't need separate export.

**File:** `crates/fireshark-mcp/src/server.rs`

- [ ] Add the new tool request structs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListStreamsRequest {
    session_id: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct GetStreamRequest {
    session_id: String,
    stream_id: u32,
}
```

- [ ] Add the three new tool endpoints inside the `#[tool_router(router = tool_router)] impl FiresharkMcpServer` block:

```rust
    #[tool(description = "List TCP/UDP conversation streams in a capture session")]
    async fn list_streams(
        &self,
        Parameters(request): Parameters<ListStreamsRequest>,
    ) -> McpResult<StreamListResponse> {
        self.tools
            .list_streams(
                &request.session_id,
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(100),
            )
            .await
            .map(|streams| Json(StreamListResponse { streams }))
            .map_err(tool_error)
    }

    #[tool(description = "Get a single stream with its packet summaries")]
    async fn get_stream(
        &self,
        Parameters(request): Parameters<GetStreamRequest>,
    ) -> McpResult<StreamPacketsResponse> {
        self.tools
            .get_stream(&request.session_id, request.stream_id)
            .await
            .map(|(stream, packets)| Json(StreamPacketsResponse { stream, packets }))
            .map_err(tool_error)
    }

    #[tool(description = "Get a one-shot summary of a capture: packets, streams, protocols, endpoints, findings")]
    async fn summarize_capture(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<CaptureSummaryView> {
        self.tools
            .summarize_capture(&request.session_id)
            .await
            .map(Json)
            .map_err(tool_error)
    }
```

- [ ] Add the new response types to the server.rs imports:

```rust
use crate::model::{
    CaptureDescriptionView, CaptureSummaryView, CloseCaptureResponse, DecodeIssueListResponse,
    EndpointListResponse, FindingListResponse, OpenCaptureResponse, PacketDetailView,
    PacketListResponse, ProtocolSummaryResponse, StreamListResponse, StreamPacketsResponse,
};
```

- [ ] Update the `tool_error` function to handle `StreamNotFound`:

```rust
fn tool_error(error: ToolError) -> ErrorData {
    match error {
        error @ ToolError::Session(crate::session::SessionError::NotFound(_))
        | error @ ToolError::PacketNotFound { .. }
        | error @ ToolError::FindingNotFound { .. }
        | error @ ToolError::StreamNotFound { .. } => {
            ErrorData::resource_not_found(error.to_string(), None)
        }
        error @ ToolError::Session(crate::session::SessionError::LimitReached { .. })
        | error @ ToolError::Session(crate::session::SessionError::Analysis(_)) => {
            ErrorData::invalid_params(error.to_string(), None)
        }
    }
}
```

### Task 16: MCP tests

**File:** Add tests to existing MCP test files or create `crates/fireshark-mcp/src/tools.rs` (test module) or integration tests.

- [ ] Test `list_streams`:

```rust
#[tokio::test]
async fn list_streams_returns_stream_metadata() {
    let service = ToolService::new_default();
    let response = service.open_capture("../../fixtures/smoke/http.pcap").await.unwrap();
    let streams = service
        .list_streams(&response.session_id, 0, 100)
        .await
        .unwrap();
    assert!(!streams.is_empty());
    assert_eq!(streams[0].id, 0);
    assert!(!streams[0].protocol.is_empty());
}
```

- [ ] Test `get_stream`:

```rust
#[tokio::test]
async fn get_stream_returns_stream_packets() {
    let service = ToolService::new_default();
    let response = service.open_capture("../../fixtures/smoke/http.pcap").await.unwrap();
    let (stream, packets) = service
        .get_stream(&response.session_id, 0)
        .await
        .unwrap();
    assert_eq!(stream.id, 0);
    assert!(!packets.is_empty());
}
```

- [ ] Test `get_stream` with invalid ID:

```rust
#[tokio::test]
async fn get_stream_returns_error_for_invalid_id() {
    let service = ToolService::new_default();
    let response = service.open_capture("../../fixtures/smoke/http.pcap").await.unwrap();
    let result = service.get_stream(&response.session_id, 99999).await;
    assert!(result.is_err());
}
```

- [ ] Test `summarize_capture`:

```rust
#[tokio::test]
async fn summarize_capture_returns_combined_summary() {
    let service = ToolService::new_default();
    let response = service.open_capture("../../fixtures/smoke/http.pcap").await.unwrap();
    let summary = service
        .summarize_capture(&response.session_id)
        .await
        .unwrap();
    assert!(summary.packet_count > 0);
    assert!(summary.stream_count > 0);
    assert!(!summary.protocols.is_empty());
}
```

**Note:** Adjust the fixture path (`../../fixtures/smoke/http.pcap` or whichever pcap exists with TCP traffic) to match the actual fixture available in the workspace.

- [ ] Run `just check` to verify everything compiles and tests pass.
- [ ] Commit: `add: MCP list_streams, get_stream, summarize_capture tools`

---

## Implementation notes

### IpAddr ordering caveat

`StreamKey::new` uses `(IpAddr, u16) <= (IpAddr, u16)`. Rust's `Ord` for `IpAddr` orders V4 before V6, then by octets. This means a mixed V4/V6 tuple always puts V4 in `addr_lo`. This is acceptable since cross-AF flows within a single conversation are not expected in practice.

### AnalyzedCapture Clone

`AnalyzedCapture` derives `Clone`. The new `StreamTracker` field also derives `Clone`, so this continues to work. `HashMap<StreamKey, u32>` and `Vec<StreamMetadata>` are both `Clone`.

### DecodedFrame PartialEq

`DecodedFrame` derives `PartialEq`. The new `stream_id: Option<u32>` field participates in equality. This is correct: two frames with different stream IDs are not equal.

### No parser changes needed

`tcp.stream` and `udp.stream` are lexed as `Ident("tcp.stream")` and `Ident("udp.stream")` by the existing parser. They route to `resolve_field` in the evaluator like all dotted field paths. Only `evaluate.rs` changes.

### format_timestamp visibility

The `format_timestamp` function in `query.rs` needs to be changed from private to `pub(crate)` so `tools.rs` can use it for `summarize_capture`. The `civil_from_days` helper it calls stays private since it's only used within `format_timestamp`.
