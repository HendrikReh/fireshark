# Timestamps and Original Length — Design Spec

## Purpose

Add packet timestamps and original wire length to the Frame model, threading them through the reader, pipeline, summary, CLI output, and MCP response model. This completes the crawl phase requirement to "iterate frames with timestamps, lengths, and raw bytes."

## Frame Changes

Add two fields to `Frame` and `FrameBuilder` in `fireshark-core::frame`:

- `timestamp: Option<Duration>` — time since Unix epoch from pcap/pcapng headers. `Option` because synthetic/test frames and pcapng `SimplePacket` blocks may not have one. Pre-1970 timestamps cannot be represented (not a concern for packet captures).
- `original_len: usize` — wire length before snaplen truncation. Source type in pcap-file is `u32`; convert via `as usize` for consistency with the existing `captured_len: usize`. Defaults to `captured_len` when not explicitly set by the builder.

Use `std::time::Duration` from the standard library. No external datetime dependency.

## Reader Changes

In `fireshark-file::reader`, extract timestamp and original length from packet headers:

- **pcap**: `PcapPacket` has `timestamp` (Duration since epoch) and `orig_len: u32`. Both always available.
- **pcapng `EnhancedPacket`**: has `timestamp` (Duration since epoch) and `original_len: u32`. Both available.
- **pcapng `SimplePacket`**: has no timestamp (`None`). Has `original_len: u32` from the block header (may differ from `data.len()` due to snaplen).

Pass these through `FrameBuilder::timestamp()` and `FrameBuilder::original_len()`.

## Summary Changes

Add `timestamp: Option<Duration>` to `PacketSummary` in `fireshark-core::summary`.

Change `PacketSummary::from_packet` signature to accept a `&Frame`:

```rust
pub fn from_packet(packet: &Packet, frame: &Frame) -> Self
```

This replaces the current `(packet: &Packet, length: usize)` signature. The timestamp and length are read from the frame. Update the call site in `DecodedFrame::summary()` (pipeline.rs) accordingly.

Also update the `From<&Frame> for PacketSummary` impl to populate the timestamp field.

No changes needed to `Pipeline` or `DecodedFrame` themselves — they already bundle `Frame` + `Packet`.

## CLI Output Changes

Add a timestamp column between the packet number and protocol in the summary command output:

```text
   1  2026-03-15T12:34:56.789Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

- Format as ISO 8601 UTC with millisecond precision.
- Frames without a timestamp show `-` in the timestamp column.
- The length column shows `captured_len` (same as today). `original_len` is available via the frame but not displayed in the CLI — analysts interested in truncation can inspect via the MCP server.

### Timestamp Formatting

Implement a manual epoch-to-UTC conversion using a known civil-time algorithm (e.g., Howard Hinnant's `civil_from_days`). This avoids adding `chrono` or `time` as a dependency. The algorithm handles leap years and century rules correctly. Leap seconds are not relevant (pcap timestamps are Unix epoch, which doesn't count leap seconds).

## MCP Model Changes

In `fireshark-mcp::model`:

- Add `timestamp: Option<String>` (ISO 8601 or null) to `PacketSummaryView`.
- Add `original_len: usize` to `PacketSummaryView` and `PacketDetailView`.
- Populate both directly from `DecodedFrame::frame()` (not from `PacketSummary`, since the core summary does not carry `original_len`).

## Testing

- Update pcap/pcapng fixture tests to assert `frame.timestamp()` is `Some(_)` and the value is plausible (after 2020-01-01, before 2030-01-01 — fixtures were handcrafted in 2026).
- Verify `SimplePacket` frames produce `timestamp: None`.
- Verify `original_len` defaults to `captured_len` when the builder does not set it.
- Update CLI integration test (`summary_command_prints_one_packet_row`) to match new output format with timestamp column.
- Update MCP tests that check `PacketSummaryView` shape to include `timestamp` and `original_len` fields.
- Add a unit test for the timestamp formatting function covering known epoch values.

## Out of Scope

- Timezone display options (always UTC in crawl)
- Relative/delta timestamp modes (run phase concern)
- External datetime library dependency
- Displaying `original_len` in CLI output
