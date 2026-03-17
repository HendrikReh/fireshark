# Fireshark

[![Version](https://img.shields.io/badge/version-0.5.1-blue)]()
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-351%20passing-brightgreen)]()
[![Status](https://img.shields.io/badge/phase-walk-blue)]()

Packet analyzer built for LLMs and humans. Rust-native protocol dissection with an MCP server that lets an AI assistant perform security audits, and a color-coded CLI for direct analysis.

## Table of Contents

- [Elevator Pitch](#elevator-pitch)
- [Why native dissectors when tshark exists?](#why-native-dissectors-when-tshark-exists)
- [Features](#features)
- [Quick Start](#quick-start)
- [Workspace Layout](#workspace-layout)
- [MCP Server](#mcp-server)
  - [Connecting to Claude Code](#connecting-to-claude-code)
  - [Connecting to Codex](#connecting-to-codex)
  - [Example LLM Workflow](#example-llm-workflow)
- [Development](#development)
- [Phases](#phases)
- [Design Rules](#design-rules)
- [Documentation](#documentation)
- [License](#license)

## Elevator Pitch

Fireshark gives an LLM the same analytical toolkit a human analyst gets from Wireshark — packet queries, protocol decoding, display filters, stream tracking, and security audit heuristics — through structured MCP tool calls. For humans, it's a fast, color-coded CLI that decodes 10 protocols, follows TCP/UDP conversations, and runs 7 automated security checks. Everything is library-first: one Rust workspace, 8 crates, 351 tests, zero unsafe code.

## Why native dissectors when tshark exists?

Fireshark includes an optional tshark backend for broad protocol coverage, but the native Rust dissectors are the core of the product — not redundant with tshark.

| Capability | Native | tshark |
|-----------|--------|--------|
| Typed, structured layers (`TcpLayer.flags.syn`, `DnsLayer.query_name`) | Yes | No — flat string fields |
| Security audit engine (7 heuristics: scan detection, DNS tunneling, etc.) | Yes | No — can't feed typed data into audit logic |
| Stream tracking with `tcp.stream` filter and `follow` command | Yes | No — tshark's conversations are opaque |
| Display filter evaluation (`tcp.flags.syn and ip.ttl > 64`) | Yes | No — separate filter engine, results can't feed fireshark pipeline |
| Color-coded hex dump with per-layer byte spans | Yes | No — tshark doesn't expose byte offsets |
| Zero external dependencies — works without Wireshark installed | Yes | No — requires tshark binary |
| Broad protocol identification (3,000+ protocols) | 10 protocols | Yes |
| Quick triage of unsupported protocols | No | Yes |
| Correctness oracle for differential testing | Reference | Validation |

**Use native** for deep analysis, audits, stream tracking, and filtering. **Use tshark** for broad protocol triage and as a correctness oracle. Both backends share the same CLI and MCP surfaces.

## Features

- **Capture file reading** — pcap and pcapng with timestamps and original wire length
- **Protocol dissection** — Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS (ClientHello + ServerHello) with full RFC field extraction
- **TLS handshake analysis** — heuristic dispatch on any TCP port, SNI extraction, cipher suites, ALPN, supported versions, signature algorithms, key share groups
- **DNS response parsing** — A/AAAA answer records with typed answer data
- **Stream tracking** — TCP/UDP conversation tracking with canonical 5-tuple keys, stream IDs, and per-stream statistics
- **Color-coded CLI** — Wireshark-style protocol coloring in summary output
- **Packet detail view** — decoded layer tree with color-coded hex dump (`fireshark detail`)
- **Follow stream** — `fireshark follow` shows all packets in a conversation by stream ID
- **Display filters** — Wireshark-style expression language (`-f "tcp and port 443"`, `tcp.stream == 0`)
- **MCP server** — offline capture analysis for LLM-driven workflows and security audits, including stream and summary tools
- **Fuzz testing** — cargo-fuzz infrastructure with two fuzz targets

## Quick Start

```bash
# Build and verify
just check

# Packet summary with color-coded output
cargo run -p fireshark-cli -- summary your-capture.pcap

# With a display filter
cargo run -p fireshark-cli -- summary your-capture.pcap -f "tcp and port 443"

# Inspect a single packet (layer tree + hex dump)
cargo run -p fireshark-cli -- detail your-capture.pcap 1

# Follow a TCP/UDP conversation
cargo run -p fireshark-cli -- follow your-capture.pcap 0

# Capture statistics
cargo run -p fireshark-cli -- stats your-capture.pcap

# Security audit
cargo run -p fireshark-cli -- audit your-capture.pcap

# Use tshark backend for broader protocol coverage
cargo run -p fireshark-cli -- summary --backend tshark your-capture.pcap
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

# TLS handshakes
cargo run -p fireshark-cli -- summary capture.pcap -f "tls"

# TLS ClientHello only
cargo run -p fireshark-cli -- summary capture.pcap -f "tls.handshake.type == 1"

# TLS by cipher suite
cargo run -p fireshark-cli -- summary capture.pcap -f "tls.cipher_suite == 0x1301"

# Filter by stream ID (conversation)
cargo run -p fireshark-cli -- summary capture.pcap -f "tcp.stream == 0"
cargo run -p fireshark-cli -- summary capture.pcap -f "udp.stream == 1"
```

### Follow a Stream

```bash
# Show all packets in TCP/UDP conversation 0
cargo run -p fireshark-cli -- follow capture.pcap 0
```

```text
Stream 0: TCP 192.0.2.10:51514 ↔ 198.51.100.20:443
3 packets, 162 bytes, duration 0.200s
──────────────────────────────────────
   1  2024-01-15T10:30:45.123Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
   2  2024-01-15T10:30:45.200Z  TCP    198.51.100.20:443      -> 192.0.2.10:51514         54
   3  2024-01-15T10:30:45.300Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

### Packet Detail

```bash
cargo run -p fireshark-cli -- detail capture.pcap 1
```

Shows a decoded layer tree with field values and a color-coded hex dump where each byte is colored by its protocol layer.

## Workspace Layout

| Crate | Purpose |
|-------|---------|
| `fireshark-core` | Domain types (`Frame`, `Packet`, `Layer`, `Pipeline`, `StreamTracker`, `TrackingPipeline`), summaries, decode issues |
| `fireshark-file` | pcap and pcapng ingestion with timestamp/length extraction |
| `fireshark-dissectors` | Protocol decoders (10 protocols) with full RFC field extraction |
| `fireshark-filter` | Display filter language: lexer, parser, evaluator (including `tcp.stream`/`udp.stream`) |
| `fireshark-cli` | CLI with 6 commands: `summary`, `detail`, `stats`, `issues`, `audit`, `follow` |
| `fireshark-backend` | Backend abstraction: native pipeline and tshark subprocess adapters |
| `fireshark-tshark` | tshark subprocess discovery, execution, and output normalization |
| `fireshark-mcp` | Offline MCP server (17 tools) for LLM-driven capture analysis and security audits |

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
| Streams | `list_streams`, `get_stream` |
| Capture overview | `summarize_capture` |
| Audit | `audit_capture`, `list_findings`, `explain_finding` |

Constraints: stdio transport, offline captures, 100k packet limit, 8 concurrent sessions, 15-minute idle timeout.

### Connecting to Claude Code

Add fireshark as an MCP server so Claude can analyze packet captures during conversations:

```bash
# From the fireshark repo root — build first
cargo build -p fireshark-mcp --release

# Add to Claude Code
claude mcp add fireshark ./target/release/fireshark-mcp
```

Or add manually to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "fireshark": {
      "command": "/path/to/fireshark/target/release/fireshark-mcp"
    }
  }
}
```

Claude can then use fireshark tools directly:

> "Open `/tmp/capture.pcap` and tell me what's in it"
>
> → Claude calls `open_capture`, `summarize_capture`, then drills into findings with `list_findings` and `get_packet`

### Connecting to Codex

Add to your Codex MCP configuration (typically `codex-mcp.json` or equivalent):

```json
{
  "servers": {
    "fireshark": {
      "command": "/path/to/fireshark/target/release/fireshark-mcp",
      "transport": "stdio"
    }
  }
}
```

### Generic MCP Clients

Fireshark's MCP server uses **stdio transport** — it reads JSON-RPC from stdin and writes to stdout. Any MCP-compatible client can connect by spawning the binary as a subprocess:

```bash
# Direct stdio interaction (for testing)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | cargo run -p fireshark-mcp
```

### Example LLM Workflow

A typical analysis session through MCP:

1. **Open** — `open_capture({ path: "/tmp/traffic.pcap" })` → session_id, packet count, protocol breakdown
2. **Summarize** — `summarize_capture({ session_id })` → protocols, top endpoints, streams, findings count
3. **Audit** — `audit_capture({ session_id })` → security findings with evidence
4. **Drill down** — `get_packet({ session_id, packet_index: 42 })` → full layer decode for a suspicious packet
5. **Filter** — `list_packets({ session_id, filter: "tls and tls.handshake.type == 1" })` → all TLS ClientHellos
6. **Stream** — `get_stream({ session_id, stream_id: 5 })` → follow a conversation
7. **Close** — `close_capture({ session_id })` → free resources

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
| **Crawl** | Offline capture parsing, dissection, CLI, MCP server, display filters, stream tracking | Complete |
| **Walk** | tshark backend, capture comparison, live capture backends | Active |
| **Run** | HTTP dissector, string filters, advanced statistics, export | Planned |

## Design Rules

- File parsing stays separate from protocol dissection
- Decoding favors explicit, typed layers over ad hoc byte inspection
- APIs support streaming/iteration instead of forcing full-file loading
- Features are added in vertical slices, not as large speculative frameworks
- MCP types stay in `fireshark-mcp` — no protocol leakage into core crates

## Documentation

Detailed documentation by audience:

| Document | Audience |
|----------|----------|
| [Architect Guide](docs/stakeholders/architect.md) | System architecture, crate boundaries, design decisions, extension points |
| [Developer Guide](docs/stakeholders/developer.md) | Getting started, adding protocols/filters/commands, code patterns |
| [User Guide](docs/stakeholders/user.md) | CLI commands, display filter reference, MCP tool guide, backend selection |
| [Tester Guide](docs/stakeholders/tester.md) | Test architecture, fixtures, coverage by crate, fuzz workflow |
| [DevOps Guide](docs/stakeholders/devops.md) | CI pipeline, release checklist, dependency inventory |
| [Ops Guide](docs/stakeholders/ops.md) | Deployment, MCP server operation, runtime requirements, troubleshooting |
| [Roadmap](docs/ROADMAP.md) | Version history, planned features, current metrics |

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
Copyright 2026 Hendrik Reh <hendrik.reh@blacksmith-consulting.ai>. See [`COPYRIGHT`](COPYRIGHT).

---

**Version:** 0.5.1 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
