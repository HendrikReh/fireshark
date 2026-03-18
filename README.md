# Fireshark

[![Version](https://img.shields.io/badge/version-0.9.0-blue)]()
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-469%20passing-brightgreen)]()
[![Status](https://img.shields.io/badge/phase-walk-blue)]()

Packet analyzer built for LLMs and humans. Rust-native protocol dissection with an MCP server that lets an AI assistant perform security audits, and a color-coded CLI for direct analysis.

## Table of Contents

- [Elevator Pitch](#elevator-pitch)
- [Why native dissectors when tshark exists?](#why-native-dissectors-when-tshark-exists)
- [System Requirements](#system-requirements)
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
  - [MCP Server Reference](docs/references/mcp-server.md)
- [License](#license)

## Elevator Pitch

Fireshark gives an LLM the same analytical toolkit a human analyst gets from Wireshark — packet queries, protocol decoding, display filters, stream tracking, stream reassembly, certificate extraction, finding escalation, and security audit heuristics — through structured MCP tool calls. For humans, it's a fast, color-coded CLI that decodes 11 protocols, follows TCP/UDP conversations with payload reassembly, runs 8 automated security checks, validates checksums, and exports results as JSON. Everything is library-first: one Rust workspace, 8 crates, 469 tests, zero unsafe code.

## Why native dissectors when tshark exists?

Fireshark ships both because they solve different problems.

`tshark` is the coverage engine: it gives Fireshark access to Wireshark's very broad protocol support, mature stream reassembly, and fast triage of captures that contain protocols Fireshark does not decode natively yet.

The native Rust dissectors are the semantics engine: they give Fireshark stable, repo-owned packet types, in-process filtering, byte spans for the hex dump, stream identity, and direct inputs for audit logic. That is the part of the system Fireshark can reason about, test, fuzz, and expose through MCP without depending on an external binary's output format.

| Dimension | Native Rust | tshark |
|-----------|-------------|--------|
| Protocol breadth | Narrower: 11 core protocols | Much broader: thousands of dissectors |
| Internal data model | Repo-owned typed layers and fields | External decode output that Fireshark must normalize |
| Display filters | Smaller feature set, but in-process and integrated with Fireshark packet objects | More complete Wireshark semantics, but separate from Fireshark's native pipeline |
| Stream handling | Repo-owned stream IDs and per-stream metadata | Stronger reassembly and follow capabilities |
| Hex dump / byte-level UX | Native layer spans drive Fireshark's color-coded detail view | Not exposed in the same byte-span form |
| Audit inputs | Directly feeds Fireshark's audit engine | Requires an additional mapping layer and currently supports less |
| Runtime dependencies | No Wireshark installation required | Requires the `tshark` binary |
| Best use in Fireshark | Deterministic analysis, filtering, audits, MCP semantics | Broad protocol triage, reassembly, compatibility, validation |

### Why the native 11 protocols still matter

The native dissectors are not trying to out-Wireshark Wireshark. They cover the protocols that most of Fireshark's higher-level features actually depend on:

- **Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP** provide the packet facts that drive summaries, endpoints, ports, TTL / hop limit checks, fragmentation state, stream IDs, and several audit heuristics.
- **DNS** provides typed query names, query types, and response records, which directly support DNS-focused filtering and DNS-tunneling detection.
- **TLS ClientHello / ServerHello** provides native access to handshake metadata such as SNI, ALPN, versions, cipher selection, and key-share groups, which are useful security pivots even without full TLS decryption.
- **HTTP** provides first-packet method, URI, host, status code, and content type extraction via ASCII signature heuristic dispatch, enabling HTTP-specific filtering and audit without reassembly.

That gives Fireshark a stable core it can own end-to-end:

- typed Rust fields instead of backend-specific string parsing
- deterministic in-process filter evaluation
- native stream tracking and packet-to-stream identity
- byte spans for the color-coded hex dump
- direct inputs for the audit engine
- zero-runtime-dependency operation for the default workflow

So the practical split is:

- **Use native** when you want Fireshark-owned semantics: audits, filtering, stream identity, MCP queries, and byte-accurate packet inspection on the core protocol set.
- **Use tshark** when you want breadth: unsupported protocols, richer reassembly, quick triage, and differential validation against Wireshark.

Both backends matter. `tshark` gives Fireshark reach. The native dissectors give Fireshark its own product behavior.

## System Requirements

### Runtime

The native backend (default) has **zero external runtime dependencies** — no Wireshark, libpcap, or other system libraries required. All protocol dissection is pure Rust. A pre-built `fireshark` or `fireshark-mcp` binary is all you need.

**Pre-built binaries** for macOS (Apple Silicon) are available on the [GitHub Releases](https://github.com/HendrikReh/fireshark/releases) page.

| Dependency | Version | Required | Purpose |
|-----------|---------|----------|---------|
| [tshark](https://www.wireshark.org/) (Wireshark CLI) | 3.0.0+ | Optional | Broad protocol coverage via `--backend tshark` |

Fireshark discovers tshark automatically by checking `PATH` first, then known locations:
- `/Applications/Wireshark.app/Contents/MacOS/tshark` (macOS)
- `/usr/local/bin/tshark`
- `/usr/bin/tshark` (Linux)

```bash
# macOS
brew install --cask wireshark

# Debian/Ubuntu
sudo apt install tshark

# Fedora/RHEL
sudo dnf install wireshark-cli

# Verify
tshark --version   # must be >= 3.0.0
```

### Building from source

| Dependency | Version | Required | Purpose |
|-----------|---------|----------|---------|
| [Rust](https://www.rust-lang.org/) | 1.85+ (edition 2024) | Yes | Compiler toolchain |
| [cargo](https://doc.rust-lang.org/cargo/) | (bundled with Rust) | Yes | Build system and package manager |
| [just](https://github.com/casey/just) | any | Yes | Task runner (`just check`, `just test`, etc.) |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | any | Only for fuzzing | Fuzz testing targets |

## Features

- **Capture file reading** — pcap and pcapng with timestamps and original wire length
- **Protocol dissection** — Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS (ClientHello + ServerHello), HTTP with full RFC field extraction
- **Checksum validation** — IPv4 header, TCP, and UDP checksums verified during dissection; zero checksums (NIC offload) are skipped
- **TLS handshake analysis** — heuristic dispatch on any TCP port, SNI extraction, cipher suites, ALPN, supported versions, signature algorithms, key share groups
- **DNS response parsing** — A/AAAA answer records with typed answer data
- **Stream tracking** — TCP/UDP conversation tracking with canonical 5-tuple keys, stream IDs, and per-stream statistics
- **Color-coded CLI** — Wireshark-style protocol coloring in summary output
- **Packet detail view** — decoded layer tree with color-coded hex dump (`fireshark detail`)
- **Follow stream** — `fireshark follow` shows all packets in a conversation by stream ID, with `--payload` for reassembled TCP payload hex dump and `--http` for HTTP request/response (requires tshark backend)
- **Stream reassembly** — tshark-backed TCP stream reassembly via `follow --payload` and `follow --http`
- **TLS certificate extraction** — extract subject CN, SAN DNS names, and organization from TLS handshakes via `get_certificates` MCP tool (requires tshark backend)
- **Display filters** — Wireshark-style expression language (`-f "tcp and port 443"`, `tcp.stream == 0`) with string operators (`contains`, `matches` for regex)
- **JSON export** — `--json` flag on `summary`, `stats`, `issues`, `audit` for JSONL output (one JSON object per line, no color codes)
- **Capture comparison** — `fireshark diff <file1> <file2>` shows new/missing hosts, protocols, and ports between two captures
- **MCP server** — offline capture analysis for LLM-driven workflows and security audits, including stream, summary, and comparison tools
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

# Follow with reassembled TCP payload hex dump (requires tshark)
cargo run -p fireshark-cli -- follow your-capture.pcap 0 --payload

# Follow with HTTP request/response (requires tshark)
cargo run -p fireshark-cli -- follow your-capture.pcap 0 --http

# Capture statistics
cargo run -p fireshark-cli -- stats your-capture.pcap

# Security audit
cargo run -p fireshark-cli -- audit your-capture.pcap

# Security audit with a focused profile
cargo run -p fireshark-cli -- audit --profile security your-capture.pcap

# Security audit with custom packet limit
cargo run -p fireshark-cli -- audit --max-packets 500000 large-capture.pcap

# Compare two captures (new/missing hosts, protocols, ports)
cargo run -p fireshark-cli -- diff baseline.pcap suspect.pcap

# JSON export (JSONL: one JSON object per line, no color codes)
cargo run -p fireshark-cli -- summary your-capture.pcap --json
cargo run -p fireshark-cli -- stats your-capture.pcap --json
cargo run -p fireshark-cli -- issues your-capture.pcap --json
cargo run -p fireshark-cli -- audit your-capture.pcap --json

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

# DNS NXDOMAIN responses
cargo run -p fireshark-cli -- summary capture.pcap -f "dns.rcode == 3"

# TLS handshakes
cargo run -p fireshark-cli -- summary capture.pcap -f "tls"

# TLS ClientHello only
cargo run -p fireshark-cli -- summary capture.pcap -f "tls.handshake.type == 1"

# TLS by cipher suite
cargo run -p fireshark-cli -- summary capture.pcap -f "tls.cipher_suite == 0x1301"

# HTTP requests
cargo run -p fireshark-cli -- summary capture.pcap -f "http"

# HTTP by method
cargo run -p fireshark-cli -- summary capture.pcap -f 'http.method contains "POST"'

# HTTP by URI
cargo run -p fireshark-cli -- summary capture.pcap -f 'http.uri contains "/api"'

# HTTP by host
cargo run -p fireshark-cli -- summary capture.pcap -f 'http.host contains "example.com"'

# HTTP by status code
cargo run -p fireshark-cli -- summary capture.pcap -f "http.status_code == 200"

# HTTP by content type
cargo run -p fireshark-cli -- summary capture.pcap -f 'http.content_type contains "json"'

# Filter by stream ID (conversation)
cargo run -p fireshark-cli -- summary capture.pcap -f "tcp.stream == 0"
cargo run -p fireshark-cli -- summary capture.pcap -f "udp.stream == 1"

# String filter: case-insensitive substring match
cargo run -p fireshark-cli -- summary capture.pcap -f 'dns.qname contains "evil"'

# String filter: regex match
cargo run -p fireshark-cli -- summary capture.pcap -f 'tls.sni matches ".*\.example\.com"'
```

### Follow a Stream

```bash
# Show all packets in TCP/UDP conversation 0
cargo run -p fireshark-cli -- follow capture.pcap 0

# Show reassembled TCP payload as hex dump (requires tshark)
cargo run -p fireshark-cli -- follow capture.pcap 0 --payload

# Show HTTP request/response for a stream (requires tshark)
cargo run -p fireshark-cli -- follow capture.pcap 0 --http
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
| `fireshark-dissectors` | Protocol decoders (11 protocols) with full RFC field extraction |
| `fireshark-filter` | Display filter language: lexer, parser, evaluator (including `tcp.stream`/`udp.stream`, `contains`/`matches` string operators) |
| `fireshark-cli` | CLI with 7 commands: `summary`, `detail`, `stats`, `issues`, `audit`, `follow`, `diff` |
| `fireshark-backend` | Backend abstraction: native pipeline and tshark subprocess adapters |
| `fireshark-tshark` | tshark subprocess discovery, execution, and output normalization |
| `fireshark-mcp` | Offline MCP server (21 tools) for LLM-driven capture analysis, security audits, stream reassembly, certificate extraction, finding escalation, and capture comparison |

Other directories:

- `fixtures/` — handcrafted binary fixtures and smoke captures for testing
- `fuzz/` — cargo-fuzz targets for dissector and capture reader fuzzing
- `docs/` — design specs and implementation plans

## MCP Server

Offline MCP server for LLM-driven packet analysis and security audits. Stateful: open a capture once, get a `session_id`, reuse it for queries. For complete tool reference, see [MCP Server Reference](docs/references/mcp-server.md).

```bash
cargo run -p fireshark-mcp
```

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Streams | `list_streams`, `get_stream`, `get_stream_payload` |
| Capture overview | `summarize_capture` |
| Comparison | `compare_captures` |
| Audit | `audit_capture`, `list_findings`, `explain_finding`, `escalate_finding` |
| TLS | `get_certificates` |

Constraints: stdio transport, offline captures, configurable packet limit (default 100k), 8 concurrent sessions, 15-minute idle timeout.

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
3. **Audit** — `audit_capture({ session_id, profile: "security" })` → security findings with evidence
4. **Drill down** — `get_packet({ session_id, packet_index: 42 })` → full layer decode for a suspicious packet
5. **Filter** — `list_packets({ session_id, filter: "tls and tls.handshake.type == 1" })` → all TLS ClientHellos
6. **Stream** — `get_stream({ session_id, stream_id: 5 })` → follow a conversation
7. **Reassemble** — `get_stream_payload({ session_id, stream_id: 5 })` → reassembled TCP payload hex dump
8. **Certificates** — `get_certificates({ session_id })` → TLS certificate details (subject CN, SAN DNS, org)
9. **Escalate** — `escalate_finding({ session_id, finding_id: "f1", notes: "confirmed C2 beacon" })` → mark finding for review
10. **Close** — `close_capture({ session_id })` → free resources

### Capture Size Limits

| Surface | Packet limit | Behavior |
|---------|-------------|----------|
| `summary`, `detail`, `stats`, `issues`, `follow` | None -- streaming | Processes any capture size |
| `audit` | 100,000 (configurable via `--max-packets`) | Rejects capture if exceeded |
| MCP tools | 100,000 (configurable via `max_packets` parameter in `open_capture`) | Rejects capture if exceeded |
| tshark backend | None | Loads whatever tshark outputs |

The streaming CLI commands (`summary`, `detail`, `stats`, `issues`, `follow`) iterate packets one at a time and have no memory limit. The `audit` command and MCP tools load all packets into memory for indexing and cross-referencing, so they enforce a configurable packet limit (default 100,000).

To analyze larger captures:

```bash
# CLI: increase the limit for audit
fireshark audit --max-packets 500000 large-capture.pcap
```

For MCP, pass `max_packets` when opening:
```json
{ "path": "/tmp/large.pcap", "max_packets": 500000 }
```

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
| **Walk** | tshark backend, capture comparison, JSON export, checksum validation, tshark stream reassembly, TLS certificate extraction, live capture backends | Active |
| **Run** | String filters (contains/matches), audit profiles, HTTP dissector, finding escalation, advanced statistics | Active |

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
| [MCP Server Reference](docs/references/mcp-server.md) | MCP installation, all 21 tools with parameters, example workflow |
| [Roadmap](docs/ROADMAP.md) | Version history, planned features, current metrics |

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
Copyright 2026 Hendrik Reh <hendrik.reh@blacksmith-consulting.ai>. See [`COPYRIGHT`](COPYRIGHT).

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
