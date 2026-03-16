# Timestamps and Original Length Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add packet timestamps and original wire length to the Frame model, threading them through the reader, pipeline, summary, CLI output, and MCP response model.

**Architecture:** Add `timestamp: Option<Duration>` and `original_len: usize` to `Frame`/`FrameBuilder` in `fireshark-core`, extract them from pcap/pcapng headers in `fireshark-file`, thread through `PacketSummary`, format as ISO 8601 in CLI output, and expose in MCP views.

**Tech Stack:** Rust std `Duration`, manual Hinnant civil-time algorithm for UTC formatting, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-16-timestamps-and-original-length-design.md`

---

## Task 1: Add timestamp and original_len to Frame

**Files:**
- Modify: `crates/fireshark-core/src/frame.rs`
- Modify: `crates/fireshark-core/tests/frame_summary.rs`

- [ ] **Step 1: Write failing test for timestamp and original_len on Frame**

Add to `crates/fireshark-core/tests/frame_summary.rs`:

```rust
use std::time::Duration;

#[test]
fn frame_carries_timestamp_and_original_len() {
    let frame = Frame::builder()
        .captured_len(54)
        .original_len(64)
        .timestamp(Duration::from_secs(1_700_000_000))
        .protocol("TCP")
        .build();

    assert_eq!(frame.timestamp(), Some(Duration::from_secs(1_700_000_000)));
    assert_eq!(frame.original_len(), 64);
    assert_eq!(frame.captured_len(), 54);
}

#[test]
fn original_len_defaults_to_captured_len() {
    let frame = Frame::builder().captured_len(54).protocol("TCP").build();

    assert_eq!(frame.original_len(), 54);
    assert!(frame.timestamp().is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p fireshark-core frame_carries_timestamp -- --exact`
Expected: FAIL — `timestamp()` and `original_len()` methods do not exist

- [ ] **Step 3: Add fields to Frame and FrameBuilder**

In `crates/fireshark-core/src/frame.rs`:

Add to `Frame` struct:
```rust
timestamp: Option<Duration>,
original_len: usize,
```

Add accessor methods:
```rust
pub fn timestamp(&self) -> Option<Duration> {
    self.timestamp
}

pub fn original_len(&self) -> usize {
    self.original_len
}
```

Add to `FrameBuilder` struct:
```rust
timestamp: Option<Duration>,
original_len: Option<usize>,
```

Add builder methods:
```rust
pub fn timestamp(mut self, timestamp: Duration) -> Self {
    self.timestamp = Some(timestamp);
    self
}

pub fn original_len(mut self, original_len: usize) -> Self {
    self.original_len = Some(original_len);
    self
}
```

Update `FrameBuilder::build()` to set `original_len` from the explicit value or fall back to `captured_len`:
```rust
Frame {
    captured_len: self.captured_len,
    original_len: self.original_len.unwrap_or(self.captured_len),
    timestamp: self.timestamp,
    protocol: self.protocol,
    data: self.data,
}
```

Update `Frame::builder()` to initialize the new fields:
```rust
FrameBuilder {
    captured_len: 0,
    original_len: None,
    timestamp: None,
    protocol: String::from("UNKNOWN"),
    data: Vec::new(),
}
```

Add `use std::time::Duration;` at the top of the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p fireshark-core`
Expected: PASS (all existing tests plus the two new ones)

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-core/src/frame.rs crates/fireshark-core/tests/frame_summary.rs
git commit -m "feat: add timestamp and original_len to Frame"
```

---

## Task 2: Extract timestamp and original_len in capture reader

**Files:**
- Modify: `crates/fireshark-file/src/reader.rs`
- Modify: `crates/fireshark-file/tests/read_pcap.rs`
- Modify: `crates/fireshark-file/tests/read_pcapng.rs`

- [ ] **Step 1: Write failing tests for timestamp extraction**

Update `crates/fireshark-file/tests/read_pcap.rs` — add after the existing test:

```rust
use std::time::Duration;

#[test]
fn pcap_frames_have_timestamps() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcap");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let frame = &frames[0];
    let ts = frame.timestamp().expect("pcap frames should have timestamps");
    // Fixtures were handcrafted in 2026; plausible range: 2020-01-01 to 2030-01-01
    assert!(ts > Duration::from_secs(1_577_836_800)); // 2020-01-01
    assert!(ts < Duration::from_secs(1_893_456_000)); // 2030-01-01
    assert!(frame.original_len() > 0);
}
```

Update `crates/fireshark-file/tests/read_pcapng.rs` — add after the existing test:

```rust
use std::time::Duration;

#[test]
fn pcapng_frames_have_timestamps() {
    let fixture = repo_root().join("fixtures/smoke/minimal.pcapng");
    let frames = CaptureReader::open(fixture)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let frame = &frames[0];
    let ts = frame.timestamp().expect("pcapng frames should have timestamps");
    // Fixtures were handcrafted in 2026; plausible range: 2020-01-01 to 2030-01-01
    assert!(ts > Duration::from_secs(1_577_836_800)); // 2020-01-01
    assert!(ts < Duration::from_secs(1_893_456_000)); // 2030-01-01
    assert!(frame.original_len() > 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p fireshark-file pcap_frames_have_timestamps -- --exact`
Expected: FAIL — `frame.timestamp()` returns `None` because the reader doesn't set it

- [ ] **Step 3: Update reader to extract timestamp and original_len**

In `crates/fireshark-file/src/reader.rs`, update the `Iterator` impl:

For the pcap arm (around line 66-76), change the `Frame::builder()` call to:
```rust
Frame::builder()
    .captured_len(packet.data.len())
    .original_len(packet.orig_len as usize)
    .timestamp(packet.timestamp)
    .data(packet.data.into_owned())
    .protocol("UNKNOWN")
    .build()
```

For the pcapng `EnhancedPacket` arm (around line 80-86), change to:
```rust
Frame::builder()
    .captured_len(packet.data.len())
    .original_len(packet.original_len as usize)
    .timestamp(packet.timestamp)
    .data(packet.data.into_owned())
    .protocol("UNKNOWN")
    .build()
```

For the pcapng `SimplePacket` arm (around line 87-93), change to:
```rust
Frame::builder()
    .captured_len(packet.data.len())
    .original_len(packet.original_len as usize)
    .data(packet.data.into_owned())
    .protocol("UNKNOWN")
    .build()
```

Note: `SimplePacket` has no timestamp, so omit the `.timestamp()` call (it defaults to `None`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p fireshark-file`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-file/src/reader.rs crates/fireshark-file/tests/read_pcap.rs crates/fireshark-file/tests/read_pcapng.rs
git commit -m "feat: extract timestamp and original_len from capture files"
```

---

## Task 3: Thread timestamp through PacketSummary

**Files:**
- Modify: `crates/fireshark-core/src/summary.rs`
- Modify: `crates/fireshark-core/src/pipeline.rs`
- Modify: `crates/fireshark-core/tests/summary_render.rs`
- Modify: `crates/fireshark-core/tests/frame_summary.rs`

- [ ] **Step 1: Update summary_render test for new from_packet signature**

In `crates/fireshark-core/tests/summary_render.rs`, change the `from_packet` call to pass a `Frame` reference:

```rust
use std::time::Duration;
use fireshark_core::{Frame, Ipv4Layer, Layer, Packet, PacketSummary, TcpLayer};

#[test]
fn summary_renders_endpoints_for_tcp_packets() {
    let packet = Packet::new(
        vec![
            Layer::Ipv4(Ipv4Layer {
                source: Ipv4Addr::new(192, 0, 2, 10),
                destination: Ipv4Addr::new(198, 51, 100, 20),
                protocol: 6,
                fragment_offset: 0,
                more_fragments: false,
            }),
            Layer::Tcp(TcpLayer {
                source_port: 51514,
                destination_port: 443,
            }),
        ],
        vec![],
    );

    let frame = Frame::builder()
        .captured_len(60)
        .timestamp(Duration::from_secs(1_700_000_000))
        .protocol("TCP")
        .build();

    let summary = PacketSummary::from_packet(&packet, &frame);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
    assert_eq!(summary.source, "192.0.2.10:51514");
    assert_eq!(summary.destination, "198.51.100.20:443");
    assert_eq!(summary.timestamp, Some(Duration::from_secs(1_700_000_000)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fireshark-core summary_renders_endpoints -- --exact`
Expected: FAIL — `from_packet` signature mismatch and missing `timestamp` field

- [ ] **Step 3: Update PacketSummary and from_packet**

In `crates/fireshark-core/src/summary.rs`:

Add `use std::time::Duration;` and `use crate::Frame;` at the top.

Add `timestamp` field to `PacketSummary`:
```rust
pub struct PacketSummary {
    pub protocol: String,
    pub length: usize,
    pub source: String,
    pub destination: String,
    pub timestamp: Option<Duration>,
}
```

Update `From<&Frame>` impl to include timestamp:
```rust
impl From<&Frame> for PacketSummary {
    fn from(frame: &Frame) -> Self {
        Self {
            protocol: frame.protocol().to_string(),
            length: frame.captured_len(),
            source: String::new(),
            destination: String::new(),
            timestamp: frame.timestamp(),
        }
    }
}
```

Change `from_packet` signature from `(packet: &Packet, length: usize)` to `(packet: &Packet, frame: &Frame)`:
```rust
pub fn from_packet(packet: &Packet, frame: &Frame) -> Self {
    let protocol = packet
        .layers()
        .iter()
        .rev()
        .find(|layer| !matches!(layer, Layer::Ethernet(_)))
        .map(Layer::name)
        .unwrap_or("Unknown")
        .to_string();

    let (source, destination) = format_endpoints(packet);

    Self {
        protocol,
        length: frame.captured_len(),
        source,
        destination,
        timestamp: frame.timestamp(),
    }
}
```

- [ ] **Step 4: Update DecodedFrame::summary() call site**

In `crates/fireshark-core/src/pipeline.rs`, update line 26:

```rust
pub fn summary(&self) -> PacketSummary {
    PacketSummary::from_packet(&self.packet, &self.frame)
}
```

- [ ] **Step 5: Update frame_summary test**

In `crates/fireshark-core/tests/frame_summary.rs`, add the timestamp assertion:

```rust
use fireshark_core::{Frame, PacketSummary};

#[test]
fn summary_includes_protocol_and_length() {
    let frame = Frame::builder().captured_len(60).protocol("TCP").build();
    let summary = PacketSummary::from(&frame);

    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
    assert!(summary.timestamp.is_none());
}
```

- [ ] **Step 6: Run all core tests**

Run: `cargo test -p fireshark-core`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/fireshark-core/src/summary.rs crates/fireshark-core/src/pipeline.rs crates/fireshark-core/tests/summary_render.rs crates/fireshark-core/tests/frame_summary.rs
git commit -m "feat: thread timestamp through PacketSummary"
```

---

## Task 4: Add ISO 8601 timestamp formatting to CLI

**Files:**
- Create: `crates/fireshark-cli/src/timestamp.rs`
- Modify: `crates/fireshark-cli/src/main.rs`
- Modify: `crates/fireshark-cli/src/summary.rs`
- Modify: `crates/fireshark-cli/tests/summary_command.rs`

- [ ] **Step 1: Write failing test for timestamp formatting**

Create `crates/fireshark-cli/src/timestamp.rs` with a test:

```rust
use std::time::Duration;

/// Format a Duration (since Unix epoch) as ISO 8601 UTC with millisecond precision.
pub fn format_utc(duration: Duration) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epoch() {
        // 2023-11-14T22:13:20.000Z
        let ts = Duration::from_secs(1_700_000_000);
        assert_eq!(format_utc(ts), "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn formats_with_milliseconds() {
        let ts = Duration::from_millis(1_700_000_000_123);
        assert_eq!(format_utc(ts), "2023-11-14T22:13:20.123Z");
    }

    #[test]
    fn formats_leap_year() {
        // 2024-02-29T00:00:00.000Z
        let ts = Duration::from_secs(1_709_164_800);
        assert_eq!(format_utc(ts), "2024-02-29T00:00:00.000Z");
    }
}
```

- [ ] **Step 2: Register module and run test to verify it fails**

Add `mod timestamp;` to `crates/fireshark-cli/src/main.rs`.

Run: `cargo test -p fireshark-cli formats_known_epoch -- --exact`
Expected: FAIL — `todo!()` panics

- [ ] **Step 3: Implement format_utc using Hinnant civil_from_days**

Replace `todo!()` in `crates/fireshark-cli/src/timestamp.rs`:

```rust
pub fn format_utc(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();

    let day_secs = total_secs % 86_400;
    let hour = day_secs / 3_600;
    let minute = (day_secs % 3_600) / 60;
    let second = day_secs % 60;

    let (year, month, day) = civil_from_days((total_secs / 86_400) as i64);

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    )
}

/// Howard Hinnant's civil_from_days algorithm.
/// Converts days since Unix epoch (1970-01-01) to (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
```

- [ ] **Step 4: Run timestamp format tests**

Run: `cargo test -p fireshark-cli timestamp -- --exact`
Expected: PASS for all three tests

- [ ] **Step 5: Update CLI summary output to include timestamp column**

In `crates/fireshark-cli/src/summary.rs`, add `use crate::timestamp;` and update the `println!`:

```rust
use std::path::Path;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::timestamp;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = decoded?;
        let summary = decoded.summary();
        let ts = match summary.timestamp {
            Some(duration) => timestamp::format_utc(duration),
            None => String::from("-"),
        };
        println!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            index + 1,
            ts,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
    }

    Ok(())
}
```

- [ ] **Step 6: Update CLI integration test**

In `crates/fireshark-cli/tests/summary_command.rs`, the test asserts `stdout(contains("TCP"))` — this still passes since TCP is still in the output. But also check for the timestamp column:

```rust
#[test]
fn summary_command_prints_one_packet_row() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("TCP"))
        .stdout(contains("T00:"))  // ISO 8601 time separator (won't match "TCP")
        .stdout(contains("Z"));    // UTC suffix
}
```

- [ ] **Step 7: Run all CLI tests**

Run: `cargo test -p fireshark-cli`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crates/fireshark-cli/src/timestamp.rs crates/fireshark-cli/src/main.rs crates/fireshark-cli/src/summary.rs crates/fireshark-cli/tests/summary_command.rs
git commit -m "feat: add timestamp column to CLI summary output"
```

---

## Task 5: Add timestamp and original_len to MCP model

**Files:**
- Modify: `crates/fireshark-mcp/src/model.rs`
- Modify: `crates/fireshark-mcp/src/query.rs`
- Modify: `crates/fireshark-mcp/tests/tools.rs`
- Modify: `crates/fireshark-mcp/tests/query.rs`

- [ ] **Step 1: Add fields to MCP view structs**

In `crates/fireshark-mcp/src/model.rs`:

Add `timestamp` and `original_len` to `PacketSummaryView`:
```rust
pub struct PacketSummaryView {
    pub index: usize,
    pub timestamp: Option<String>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub original_len: usize,
    pub has_issues: bool,
}
```

Add `timestamp` and `original_len` to `PacketDetailView`:
```rust
pub struct PacketDetailView {
    pub index: usize,
    pub timestamp: Option<String>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub original_len: usize,
    pub has_issues: bool,
    pub layers: Vec<LayerView>,
    pub issues: Vec<DecodeIssueView>,
}
```

- [ ] **Step 2: Update from_frame in query.rs**

In `crates/fireshark-mcp/src/query.rs`, update `PacketSummaryView::from_frame`:

```rust
impl PacketSummaryView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = packet.summary();

        Self {
            index,
            timestamp: packet.frame().timestamp().map(format_timestamp),
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
            original_len: packet.frame().original_len(),
            has_issues: !packet.packet().issues().is_empty(),
        }
    }
}
```

Update `PacketDetailView::from_frame` to copy `timestamp` and `original_len` from the summary view:

```rust
impl PacketDetailView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = PacketSummaryView::from_frame(index, packet);

        Self {
            index: summary.index,
            timestamp: summary.timestamp,
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
            original_len: summary.original_len,
            has_issues: summary.has_issues,
            layers: packet
                .packet()
                .layers()
                .iter()
                .map(LayerView::from_layer)
                .collect(),
            issues: packet
                .packet()
                .issues()
                .iter()
                .map(DecodeIssueView::from_issue)
                .collect(),
        }
    }
}
```

Add the timestamp formatting helper at the bottom of query.rs:

```rust
fn format_timestamp(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let day_secs = total_secs % 86_400;
    let hour = day_secs / 3_600;
    let minute = (day_secs % 3_600) / 60;
    let second = day_secs % 60;
    let (year, month, day) = civil_from_days((total_secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
```

Note: The timestamp formatting is duplicated between `fireshark-cli` and `fireshark-mcp`. This is intentional — these crates are independent frontends and should not depend on each other. If a third consumer appears, extract to `fireshark-core`.

- [ ] **Step 3: Update MCP tests**

In `crates/fireshark-mcp/tests/tools.rs`, add timestamp assertion:

```rust
#[tokio::test]
async fn list_packets_tool_returns_capture_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let capture = service.open_capture(&fixture).await.unwrap();

    let packets = service
        .list_packets(&capture.session_id, 0, 10, None, None)
        .await
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
    assert!(packets[0].timestamp.is_some());
    assert!(packets[0].original_len > 0);
}
```

In `crates/fireshark-mcp/tests/query.rs`, update both tests to check new fields:

```rust
#[test]
fn list_packets_returns_packet_summaries() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packets = list_packets(&capture, 0, 10, None, None);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
    assert!(packets[0].timestamp.is_some());
    assert!(packets[0].original_len > 0);
}

#[test]
fn get_packet_returns_layers_and_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packet = get_packet(&capture, 0).unwrap();

    assert!(!packet.layers.is_empty());
    assert!(packet.issues.is_empty());
    assert!(packet.timestamp.is_some());
    assert!(packet.original_len > 0);
}
```

- [ ] **Step 4: Run all MCP tests**

Run: `cargo test -p fireshark-mcp`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-mcp/src/model.rs crates/fireshark-mcp/src/query.rs crates/fireshark-mcp/tests/tools.rs crates/fireshark-mcp/tests/query.rs
git commit -m "feat: add timestamp and original_len to MCP views"
```

---

## Task 6: Full verification

**Files:**
- No file edits unless verification reveals issues.

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: PASS

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: PASS — all tests across all crates

- [ ] **Step 4: Smoke test CLI output**

Run: `cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap`
Expected: Output includes a timestamp column in ISO 8601 format, e.g.:
```text
   1  2026-03-15T...Z           TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

- [ ] **Step 5: Commit any fixes**

If any verification step required fixes, commit them:
```bash
git add -A
git commit -m "fix: address verification issues for timestamp feature"
```
