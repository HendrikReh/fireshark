# Fireshark

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-crawl%20phase-blue)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/HendrikReh/fireshark/pulls)

Wireshark-inspired packet analyzer written in Rust and built in deliberate phases instead of as a "boil the ocean" clone.

Library-first design: the early goal is a clean capture and decode core that can support multiple frontends later, rather than jumping straight into a full desktop UI.

## What Works Today

- Read `pcap` and `pcapng` capture files
- Decode Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP
- Build structured packets through a reusable decode pipeline
- Print packet summaries through a minimal CLI
- Analyze captures via MCP server for LLM-driven workflows
- Validate behavior with fixture-based tests

## Quick Start

Requirements: Rust toolchain, `cargo`, and [`just`](https://github.com/casey/just) on your `PATH`.

```bash
just summary
# or directly:
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
```

```text
   1  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

Run the full verification gate:

```bash
just check    # fmt-check + clippy + test
```

## Workspace Layout

| Crate | Purpose |
|-------|---------|
| `fireshark-core` | Domain types, summaries, and the generic decode pipeline |
| `fireshark-file` | `pcap` and `pcapng` ingestion |
| `fireshark-dissectors` | Protocol decoders: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP |
| `fireshark-cli` | Thin CLI for exercising the library stack |
| `fireshark-mcp` | Offline MCP server for LLM-driven capture analysis |

Other directories:

- `fixtures/` — handcrafted binary fixtures used by the test suite
- `docs/plans/` — phase design and implementation planning documents

## MCP Server

Fireshark ships an offline MCP server for LLM-driven packet analysis and security audits. The server is stateful: a client opens a capture once, receives a `session_id`, and reuses it for follow-up queries.

```bash
cargo run -p fireshark-mcp
```

**Tool families:**

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Audit | `audit_capture`, `list_findings`, `explain_finding` |

**Constraints:** stdio transport only, offline captures only, 100k packet limit per capture, 8 concurrent sessions, 15-minute idle timeout.

## Development

```bash
just fmt          # cargo fmt --all
just fmt-check    # cargo fmt --all -- --check
just clippy       # cargo clippy --workspace --all-targets -- -D warnings
just test         # cargo test --workspace
just check        # all of the above
```

## Phases

The project is split into three phases so the architecture hardens around real packet data before the surface area grows.

| Phase | Focus | Status |
|-------|-------|--------|
| **Crawl** | Offline capture parsing, foundational dissection, CLI, MCP server | Active |
| **Walk** | Live capture backends, typed filtering, conversation identity | Planned |
| **Run** | Analyst workflows: packet views, display filters, follow-stream, statistics | Planned |

## Design Rules

- File parsing stays separate from protocol dissection
- Decoding favors explicit, typed layers over ad hoc byte inspection
- APIs support streaming/iteration instead of forcing full-file loading
- Features are added in vertical slices, not as large speculative frameworks
- MCP types stay in `fireshark-mcp` — no protocol leakage into core crates
