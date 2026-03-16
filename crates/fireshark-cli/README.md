# fireshark-cli

Command-line interface for the fireshark packet analyzer.

## Overview

Thin CLI binary (`fireshark`) that exercises the library stack. Provides packet summary listing with color output, packet detail inspection with hex dump, and display filter support.

## Commands

### `summary`

List packets with Wireshark-style protocol coloring.

```bash
fireshark summary capture.pcap
fireshark summary capture.pcap -f "tcp and port 443"
```

Output: one line per packet with index, timestamp (ISO 8601 UTC), protocol, source, destination, and length. Each row is colored by protocol (TCP=green, UDP=blue, ARP=yellow, ICMP=cyan).

### `detail`

Inspect a single packet with decoded layer tree and color-coded hex dump.

```bash
fireshark detail capture.pcap 1
```

Output: header line, indented layer fields for each protocol, then a hex dump where each byte is colored by its protocol layer with a legend at the bottom.

## Modules

| Module | Purpose |
|--------|---------|
| `summary.rs` | Summary command with optional display filter |
| `detail.rs` | Detail command with layer tree rendering |
| `hexdump.rs` | Color-coded hex dump formatter |
| `color.rs` | Protocol-to-color mapping (Wireshark-inspired) |
| `timestamp.rs` | ISO 8601 UTC formatting via Hinnant civil_from_days |

---

**Version:** 0.2.2 | **Last updated:** 2026-03-16 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
