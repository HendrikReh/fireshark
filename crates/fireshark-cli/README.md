# fireshark-cli

Command-line interface for the fireshark packet analyzer.

## Overview

Thin CLI binary (`fireshark`) that exercises the library stack. Provides packet summary listing with color output, packet detail inspection with hex dump, display filter support, capture statistics, decode issue listing, security audit, and stream follow.

## Commands

### `summary`

List packets with Wireshark-style protocol coloring.

```bash
fireshark summary capture.pcap
fireshark summary capture.pcap -f "tcp and port 443"
```

Output: one line per packet with index, timestamp (ISO 8601 UTC), protocol, source, destination, and length. Each row is colored by protocol (TCP=green, UDP=blue, ARP=yellow, ICMP=cyan, DNS=magenta, TLS=bright green).

### `detail`

Inspect a single packet with decoded layer tree and color-coded hex dump.

```bash
fireshark detail capture.pcap 1
```

Output: header line, indented layer fields for each protocol (including DNS transaction ID, query/response, opcode, and question/answer counts), then a hex dump where each byte is colored by its protocol layer with a legend at the bottom.

### `follow`

Show all packets belonging to a TCP/UDP conversation by stream ID.

```bash
fireshark follow capture.pcap 0
```

Output: stream header (protocol, endpoints, packet/byte count, duration), then a color-coded packet listing of every packet in the conversation.

### `stats`

Print capture statistics: packet count, stream count, duration, protocol distribution, and top endpoints.

```bash
fireshark stats capture.pcap
```

### `issues`

List all decode issues (truncated/malformed) across the capture.

```bash
fireshark issues capture.pcap
```

### `audit`

Run heuristic security analysis: scan detection, suspicious ports, cleartext credentials, DNS tunneling.

```bash
fireshark audit capture.pcap
```

## Modules

| Module | Purpose |
|--------|---------|
| `summary.rs` | Summary command with optional display filter |
| `detail.rs` | Detail command with layer tree rendering |
| `follow.rs` | Follow stream command: packets by conversation ID |
| `stats.rs` | Capture statistics: packets, streams, duration, protocols, endpoints |
| `issues.rs` | Decode issue listing |
| `audit.rs` | Security audit heuristics |
| `hexdump.rs` | Color-coded hex dump formatter |
| `color.rs` | Protocol-to-color mapping (Wireshark-inspired) |
| `timestamp.rs` | ISO 8601 UTC formatting via Hinnant civil_from_days |

---

**Version:** 0.5.1 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
