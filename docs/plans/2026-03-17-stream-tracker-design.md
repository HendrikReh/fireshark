# TCP/UDP Stream Tracker — Design Spec

## Purpose

Add conversation-level packet grouping to fireshark. A `StreamTracker` in `fireshark-core` assigns each packet a `stream_id` based on its transport-layer connection tuple, enabling conversation-based analysis across CLI, MCP, and filter surfaces. This is the foundation of v0.5 (Conversation Intelligence).

## StreamKey

Conversations are identified by a canonically ordered 5-tuple:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub addr_lo: IpAddr,
    pub port_lo: u16,
    pub addr_hi: IpAddr,
    pub port_hi: u16,
    pub protocol: u8,
}
```

Both directions of a conversation (client→server and server→client) normalize to the same key. The "lower" endpoint comes first, determined by comparing `(addr, port)` lexicographically. This is stateless — no SYN tracking needed — and works for partial captures where the handshake is missing.

The `protocol` field distinguishes TCP (6) and UDP (17) conversations on the same endpoints.

**Non-goal:** Cross-address-family tracking. If the same logical host appears as `192.168.1.1` (IPv4) and `::ffff:192.168.1.1` (IPv6-mapped) in different packets, they produce different `StreamKey`s. This is acceptable for offline pcap analysis where mixed-AF flows are rare.

### Normalization

```rust
impl StreamKey {
    pub fn new(src_addr: IpAddr, src_port: u16, dst_addr: IpAddr, dst_port: u16, protocol: u8) -> Self {
        if (src_addr, src_port) <= (dst_addr, dst_port) {
            Self { addr_lo: src_addr, port_lo: src_port, addr_hi: dst_addr, port_hi: dst_port, protocol }
        } else {
            Self { addr_lo: dst_addr, port_lo: dst_port, addr_hi: src_addr, port_hi: src_port, protocol }
        }
    }
}
```

The comparison `(IpAddr, u16) <= (IpAddr, u16)` uses the `Ord` implementation on `IpAddr` (v4 before v6, then by octets) and then port number.

## StreamMetadata

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMetadata {
    // Note: derives Clone to satisfy AnalyzedCapture's Clone derive
    pub id: u32,
    pub key: StreamKey,
    pub packet_count: usize,
    pub byte_count: usize,
    pub first_seen: Option<Duration>,
    pub last_seen: Option<Duration>,
}
```

`byte_count` is the sum of `frame.captured_len()` for all packets in the stream. This uses captured length (not wire length) so it reflects the actual bytes available for analysis, consistent with Wireshark's "Bytes" column in conversation statistics. `first_seen` and `last_seen` are from `frame.timestamp()`.

## StreamTracker

```rust
pub struct StreamTracker {
    streams: HashMap<StreamKey, u32>,
    metadata: Vec<StreamMetadata>,
    next_id: u32,
}
```

### API

```rust
impl StreamTracker {
    pub fn new() -> Self
    pub fn assign(&mut self, decoded: &DecodedFrame) -> Option<u32>
    pub fn streams(&self) -> &[StreamMetadata]
    pub fn get(&self, stream_id: u32) -> Option<&StreamMetadata>
    pub fn stream_count(&self) -> usize
}
```

`assign()` extracts IP addresses and transport ports from the packet's layers. If the packet has no transport layer (e.g., ARP, Ethernet-only), returns `None`. Otherwise, creates or looks up the `StreamKey` in the map, updates metadata, and returns the `stream_id`.

Extraction logic:
1. Find `Layer::Ipv4` or `Layer::Ipv6` → get src/dst addresses
2. Find `Layer::Tcp` or `Layer::Udp` → get src/dst ports and protocol number
3. If both found, construct `StreamKey::new(src_addr, src_port, dst_addr, dst_port, protocol)`
4. If either missing, return `None`

## DecodedFrame Changes

Add `stream_id: Option<u32>` to `DecodedFrame`:

```rust
pub struct DecodedFrame {
    frame: Frame,
    packet: Packet,
    stream_id: Option<u32>,
}
```

New accessor: `pub fn stream_id(&self) -> Option<u32>`.

Update `DecodedFrame::new()` to initialize `stream_id: None`. Add `pub fn with_stream_id(mut self, id: Option<u32>) -> Self` for the pipeline to set it.

## Pipeline Changes

The existing `Pipeline` stays unchanged (no tracking, `stream_id` always `None`).

Add a new `TrackingPipeline` wrapper:

```rust
pub struct TrackingPipeline<I, D> {
    inner: Pipeline<I, D>,
    tracker: StreamTracker,
}
```

### API

```rust
impl<I, D> TrackingPipeline<I, D> {
    pub fn new(frames: I, decoder: D) -> Self
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

impl<I, D> TrackingPipeline<I, D> {
    pub fn into_tracker(self) -> StreamTracker
    pub fn tracker(&self) -> &StreamTracker
}
```

`into_tracker()` consumes the pipeline and returns the tracker with all accumulated stream metadata. `tracker()` provides a reference during iteration (for progress reporting).

## CLI Integration

### New command: `fireshark follow <file> <stream-id>`

Create `crates/fireshark-cli/src/follow.rs`:

1. Open capture with `TrackingPipeline`
2. Collect all `DecodedFrame`s
3. Find the stream metadata by ID
4. Print stream header (key, packet count, bytes, duration)
5. Print all packets belonging to that stream in summary format (with color)

If `stream_id` is not found, print error and exit non-zero.

Duration formatting: if both `first_seen` and `last_seen` are Some, compute `last_seen - first_seen` and format as seconds/milliseconds.

### Update `stats` command

Add stream count to the stats output:

```
Streams:    45  (32 TCP, 13 UDP)
```

The `stats` command needs to switch from `Pipeline` to `TrackingPipeline` to get stream data.

### Update `summary` command

No changes to summary format. Stream IDs are available on each `DecodedFrame` but not displayed in v0.5. (A `--streams` grouping mode is a v0.6 candidate.)

## MCP Integration

### New tool: `list_streams(session_id, offset?, limit?)`

Returns paginated stream metadata:

```json
{
    "streams": [
        {
            "id": 0,
            "protocol": "TCP",
            "endpoint_a": "192.168.1.2:51514",
            "endpoint_b": "198.51.100.20:443",
            "packet_count": 12,
            "byte_count": 3842,
            "duration_ms": 234
        }
    ]
}
```

### New tool: `get_stream(session_id, stream_id)`

Returns all packet summaries belonging to the stream, using the existing `PacketSummaryView` format with an added `stream_id` field.

### New tool: `summarize_capture(session_id)`

Combines in a single response:
- Packet count, stream count
- First/last timestamp, duration
- Protocol distribution (from `summarize_protocols`)
- Top 10 endpoints (from `top_endpoints`)
- Finding count (from `audit_capture`)

This reduces the common "tell me about this capture" workflow from 4 MCP round-trips to 1.

`summarize_capture` calls the existing `summarize_protocols`, `top_endpoints` methods on `ToolService` internally, and reads the cached findings from `CaptureSession::findings()` (lazy cache, no fresh audit triggered). The stream count comes from the stored `StreamTracker`.

### AnalyzedCapture changes

`AnalyzedCapture::open()` switches from `Pipeline` to `TrackingPipeline`. The `StreamTracker` is stored alongside the packets. New accessors:

```rust
pub fn streams(&self) -> &[StreamMetadata]
pub fn stream_packets(&self, stream_id: u32) -> Vec<(usize, &DecodedFrame)>
```

`stream_packets` returns packet index + frame pairs for a given stream, filtered from the stored packets.

## Filter Integration

### New fields

| Field | Source | Type |
|-------|--------|------|
| `tcp.stream` | `decoded.stream_id()` when protocol is TCP | Integer |
| `udp.stream` | `decoded.stream_id()` when protocol is UDP | Integer |

These resolve from `DecodedFrame::stream_id()`, not from any layer. The evaluator needs access to the `DecodedFrame` (which it already has) and checks whether the packet's protocol matches.

For `tcp.stream`, return the stream_id only if the packet has a `Layer::Tcp`. For `udp.stream`, only if it has `Layer::Udp`. This prevents `tcp.stream == 5` from matching a UDP stream that happens to have id 5.

**Parser note:** No parser changes needed — `tcp.stream` is lexed as `Ident("tcp.stream")` and routed to `resolve_field` in the evaluator, same as all dotted field paths. Only `evaluate.rs` changes.

### Bare field check

`tcp.stream` as a bare field returns `true` if the packet belongs to any TCP stream (i.e., has a non-None stream_id and has a TCP layer). Equivalent to "this packet is part of a tracked TCP conversation."

## New Types in fireshark-core

- `StreamKey` — canonical 5-tuple
- `StreamMetadata` — per-stream statistics
- `StreamTracker` — assigns and tracks streams
- `TrackingPipeline` — pipeline wrapper with stream tracking

All exported from `fireshark-core::lib`.

## New Files

- `crates/fireshark-core/src/stream.rs` — StreamKey, StreamMetadata, StreamTracker
- `crates/fireshark-cli/src/follow.rs` — follow command

## Modified Files

- `crates/fireshark-core/src/pipeline.rs` — DecodedFrame stream_id field, TrackingPipeline
- `crates/fireshark-core/src/lib.rs` — export new types
- `crates/fireshark-cli/src/main.rs` — add follow command
- `crates/fireshark-cli/src/stats.rs` — switch to TrackingPipeline, show stream count
- `crates/fireshark-filter/src/evaluate.rs` — tcp.stream / udp.stream fields
- `crates/fireshark-mcp/src/analysis.rs` — use TrackingPipeline, store tracker
- `crates/fireshark-mcp/src/server.rs` — add list_streams, get_stream, summarize_capture tools
- `crates/fireshark-mcp/src/tools.rs` — tool handler methods
- `crates/fireshark-mcp/src/model.rs` — StreamView, CapturesSummaryView types
- `crates/fireshark-mcp/src/query.rs` — stream query functions

## Testing

### Unit tests (fireshark-core)
- `stream_key_normalizes_direction` — (A:80, B:12345) == (B:12345, A:80)
- `stream_tracker_assigns_same_id_for_both_directions` — client→server and server→client get same id
- `stream_tracker_assigns_different_ids_for_different_streams` — different port pairs get different ids
- `stream_tracker_returns_none_for_non_transport_packets` — ARP packet gets None
- `stream_metadata_tracks_packet_count_and_bytes` — verify counts after multiple assigns
- `tracking_pipeline_assigns_stream_ids` — iterate, check stream_id is set
- `decoded_frame_stream_id_is_none_by_default` — basic Pipeline still yields None

### Integration tests (fireshark-cli)
- `follow_command_shows_stream_packets` — verify output contains stream header + packet rows
- `follow_command_fails_for_invalid_stream_id` — non-existent stream, non-zero exit
- `stats_command_shows_stream_count` — verify "Streams:" appears in output

### MCP tests
- `list_streams_returns_stream_metadata` — open capture, list streams, verify count
- `get_stream_returns_stream_packets` — open capture, get stream 0, verify packets

## Out of Scope

- TCP state machine (SYN/FIN tracking, connection state)
- Stream reassembly (ordering payloads into a byte stream)
- Stream-grouped summary display (`--streams` flag)
- Half-open connection detection (Spec 2: connection anomaly audit)
- Stream timeout/expiration for live capture
