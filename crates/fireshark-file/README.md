# fireshark-file

Capture file ingestion for the fireshark packet analyzer.

## Overview

Reads pcap and pcapng capture files and yields `Frame` objects with timestamps, original wire length, and raw packet bytes. Supports both little-endian and big-endian pcap variants.

## Usage

```rust
use fireshark_file::CaptureReader;

let reader = CaptureReader::open("capture.pcap")?;
for frame in reader {
    let frame = frame?;
    println!("{} bytes at {:?}", frame.captured_len(), frame.timestamp());
}
```

## Supported Formats

- **pcap** — all four magic variants (little/big endian, microsecond/nanosecond)
- **pcapng** — Enhanced Packet Blocks and Simple Packet Blocks

## Constraints

- Only Ethernet link type is supported; other link types are rejected at open time
- pcapng files are validated for link type across all interface descriptions before reading packets
- Timestamps are extracted as `Duration` since Unix epoch (nanosecond precision from pcap-file crate)

## Dependencies

- `fireshark-core` — for `Frame` and `FrameBuilder`
- `pcap-file` — pcap/pcapng parsing
- `thiserror` — error types

---

**Version:** 0.6.0 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
