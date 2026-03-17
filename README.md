# Fireshark

[![Version](https://img.shields.io/badge/version-0.3.0-blue)]()
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-216%20passing-brightgreen)]()
[![Status](https://img.shields.io/badge/phase-crawl-blue)]()

Wireshark-inspired packet analyzer written in Rust. Library-first, built in deliberate phases instead of as a "boil the ocean" clone.

## Features

- **Capture file reading** — pcap and pcapng with timestamps and original wire length
- **Protocol dissection** — Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS with full RFC field extraction
- **Color-coded CLI** — Wireshark-style protocol coloring in summary output
- **Packet detail view** — decoded layer tree with color-coded hex dump (`fireshark detail`)
- **Display filters** — Wireshark-style expression language (`-f "tcp and port 443"`)
- **MCP server** — offline capture analysis for LLM-driven workflows and security audits
- **Fuzz testing** — cargo-fuzz infrastructure with two fuzz targets

## Quick Start

```bash
# Packet summary with color-coded output
just summary

# Or directly
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
```

```text
   1  1970-01-01T00:00:01.000Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

### Display Filters

```bash
# Filter by protocol
cargo run -p fireshark-cli -- summary capture.pcap -f "tcp"

# Filter by port
cargo run -p fireshark-cli -- summary capture.pcap -f "port 443"

# Complex expressions
cargo run -p fireshark-cli -- summary capture.pcap -f "tcp and port 443 and ip.ttl > 64"

# Address filtering with CIDR
cargo run -p fireshark-cli -- summary capture.pcap -f "src 10.0.0.0/8"

# Boolean field checks
cargo run -p fireshark-cli -- summary capture.pcap -f "tcp.flags.syn and not tcp.flags.ack"

# DNS queries only
cargo run -p fireshark-cli -- summary capture.pcap -f "dns and not dns.qr"

# DNS by transaction ID
cargo run -p fireshark-cli -- summary capture.pcap -f "dns.id == 0x1234"
```

### Packet Detail

```bash
cargo run -p fireshark-cli -- detail capture.pcap 1
```

Shows a decoded layer tree with field values and a color-coded hex dump where each byte is colored by its protocol layer.

## Workspace Layout

| Crate | Purpose |
|-------|---------|
| `fireshark-core` | Domain types (`Frame`, `Packet`, `Layer`, `Pipeline`), summaries, decode issues |
| `fireshark-file` | pcap and pcapng ingestion with timestamp/length extraction |
| `fireshark-dissectors` | Protocol decoders with full RFC field extraction |
| `fireshark-filter` | Display filter language: lexer, parser, evaluator |
| `fireshark-cli` | CLI with `summary` and `detail` commands, color output, hex dump |
| `fireshark-mcp` | Offline MCP server for LLM-driven capture analysis |

Other directories:

- `fixtures/` — handcrafted binary fixtures and smoke captures for testing
- `fuzz/` — cargo-fuzz targets for dissector and capture reader fuzzing
- `docs/` — design specs and implementation plans

## MCP Server

Offline MCP server for LLM-driven packet analysis and security audits. Stateful: open a capture once, get a `session_id`, reuse it for queries.

```bash
cargo run -p fireshark-mcp
```

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Audit | `audit_capture`, `list_findings`, `explain_finding` |

Constraints: stdio transport, offline captures, 100k packet limit, 8 concurrent sessions, 15-minute idle timeout.

## Development

Requirements: Rust toolchain, `cargo`, and [`just`](https://github.com/casey/just).

```bash
just fmt          # cargo fmt --all
just fmt-check    # cargo fmt --all -- --check
just clippy       # cargo clippy --workspace --all-targets -- -D warnings
just test         # cargo test --workspace
just check        # all of the above
```

### Fuzz Testing

```bash
cd fuzz
cargo fuzz run fuzz_decode_packet -- -max_total_time=60
cargo fuzz run fuzz_capture_reader -- -max_total_time=60
```

## Phases

| Phase | Focus | Status |
|-------|-------|--------|
| **Crawl** | Offline capture parsing, dissection, CLI, MCP server, display filters | Active |
| **Walk** | Live capture backends, conversation identity, stream tracking | Planned |
| **Run** | Analyst workflows: follow-stream, advanced statistics, extended filter language | Planned |

## Design Rules

- File parsing stays separate from protocol dissection
- Decoding favors explicit, typed layers over ad hoc byte inspection
- APIs support streaming/iteration instead of forcing full-file loading
- Features are added in vertical slices, not as large speculative frameworks
- MCP types stay in `fireshark-mcp` — no protocol leakage into core crates

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
Copyright 2026 Hendrik Reh <hendrik.reh@blacksmith-consulting.ai>. See [`COPYRIGHT`](COPYRIGHT).

---

**Version:** 0.3.0 | **Last updated:** 2026-03-16 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
