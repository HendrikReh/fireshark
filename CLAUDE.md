# CLAUDE.md

## Project Overview

Fireshark is a packet analyzer built for LLMs and humans, written in Rust. It is library-first and built in phases (crawl/walk/run). Currently in the **walk** phase: 10 protocol dissectors, display filter language with string operators (`contains`, `matches`), TCP/UDP stream tracking, tshark-backed stream reassembly (`follow --payload`, `follow --http`), TLS certificate extraction, checksum validation, 8 security audit heuristics with audit profiles (`--profile security|dns|quality`), 20 MCP tools, 7 CLI commands, JSON export, capture comparison, and an optional tshark backend.

## Workspace Layout

| Crate | Purpose |
|---|---|
| `fireshark-core` | Domain types (`Layer`, `Packet`, `Frame`, `Pipeline`, `StreamTracker`, `TrackingPipeline`), summaries, decode issues |
| `fireshark-dissectors` | Protocol decoders: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS ClientHello, TLS ServerHello |
| `fireshark-filter` | Display filter language: lexer, parser, evaluator (including `tcp.stream`/`udp.stream`, `contains`/`matches` string operators, `dns.qname`/`tls.sni` string-typed fields). Depends on `regex` crate |
| `fireshark-file` | pcap and pcapng file ingestion |
| `fireshark-cli` | Thin CLI binary (`fireshark`) with 7 commands: `summary`, `detail`, `stats`, `issues`, `audit`, `follow`, `diff`. Supports `--json` flag on `summary`, `stats`, `issues`, `audit`. Audit supports `--profile security|dns|quality` |
| `fireshark-backend` | Backend abstraction: native pipeline and tshark subprocess adapters |
| `fireshark-tshark` | tshark subprocess discovery, execution, and output normalization |
| `fireshark-mcp` | Offline MCP server (20 tools) for LLM-driven capture analysis, security audits, stream reassembly, certificate extraction, and capture comparison |

- `fixtures/bytes/` — handcrafted binary blobs used in unit tests
- `fixtures/smoke/` — small pcap files for integration/CLI tests
- `docs/plans/` — phase design documents

## Build & Verify

Requires: Rust toolchain, `cargo`, `just`

```bash
just check       # fmt-check + clippy + test (the full gate)
just test        # cargo test --workspace
just clippy      # cargo clippy --workspace --all-targets -- -D warnings
just fmt         # cargo fmt --all
just fmt-check   # cargo fmt --all -- --check
```

Always run `just check` before considering work complete.

## Code Conventions

- **Rust edition 2024**
- Clippy runs with `-D warnings` — all warnings are errors
- Errors use `thiserror` derive macros (`DecodeError` in dissectors, `ReadError` in file)
- No `unwrap()` or `expect()` on data derived from untrusted packet input
- Dissector parse functions return `Result<T, DecodeError>` where `T` is either a `Layer` or `NetworkPayload`
- Each dissector module defines protocol constants (`ETHER_TYPE`, `IP_PROTOCOL`) at the top
- Layer types are plain structs with public fields, defined in `fireshark-core::layer`
- The `Layer` enum in core wraps each protocol's typed layer struct
- The decode pipeline is generic over frame source and decoder function
- `TrackingPipeline` wraps `Pipeline` to assign stream IDs via `StreamTracker` during iteration
- `StreamTracker` maps canonical 5-tuples (`StreamKey`) to monotonic stream IDs with per-stream metadata
- Application-layer protocols (e.g., DNS) are dispatched by port number after transport-layer decoding (UDP port 53 for DNS)
- TLS uses heuristic dispatch on any TCP port by inspecting the record header bytes (`0x16 0x03`), not port-based dispatch

## Dissector Pattern

Each protocol dissector in `fireshark-dissectors/src/` follows this structure:

1. Module-level constants (`ETHER_TYPE`, `IP_PROTOCOL`, `MIN_HEADER_LEN`)
2. A `parse(bytes: &[u8], ...)` function that validates and decodes
3. Explicit bounds checks before every slice access
4. Returns `DecodeError::Truncated` for short buffers, `DecodeError::Malformed` for invalid fields. Checksum failures produce `DecodeIssueKind::ChecksumMismatch` (zero checksums from NIC offload are skipped)
5. Network-layer dissectors (IPv4, IPv6) return `NetworkPayload` with payload slice and offset
6. Link/transport-layer dissectors return `Layer` directly
7. Application-layer dissectors use port-based (DNS on UDP 53) or heuristic dispatch (TLS on any TCP port via record header inspection)

## Testing

- Dissector tests use `include_bytes!` with fixtures from `fixtures/bytes/`
- File reader tests use pcap/pcapng files from `fixtures/smoke/`
- CLI tests use `assert_cmd` and `predicates`
- Tests assert on layer presence, field values, and error cases (truncation, malformation)
- Add fixture files for new protocols rather than constructing bytes inline

## Issue Tracking

Uses **bd** (beads) — see AGENTS.md for full workflow. Do not use markdown TODOs.

## Design Rules

- File parsing stays separate from protocol dissection
- Decoding favors explicit, typed layers over ad hoc byte inspection
- APIs support streaming/iteration, not full-file loading
- Features are added in vertical slices, not speculative frameworks
- MCP types stay in `fireshark-mcp` — no protocol leakage into core crates
- Public features must be accessible both via MCP (for LLM-driven workflows) and via CLI (for direct human use)

## Native/tshark Ownership Model

Native dissectors own the packet facts fireshark reasons over. tshark owns breadth, reassembly, and deep long-tail protocol coverage.

**Keep native** — the control plane:
- Ethernet, ARP, IPv4 base header, IPv6 base header, TCP base header, UDP, ICMP common fields
- Checksum validation (IPv4, TCP, UDP)
- Layer byte spans for hex dump coloring
- Typed fields that drive display filters (`tcp.flags.syn`, `dns.qname`, `tls.sni`)
- Stream identity (`StreamKey` from IP+port, `StreamTracker` metadata)
- Audit heuristic inputs (flag accumulation, endpoint counting, DNS query analysis)
- DNS query name + basic A/AAAA answers (audit engine depends on `query_name`)
- TLS ClientHello/ServerHello metadata (SNI, ALPN, cipher suites, versions)

**Delegate to tshark** — the data plane:
- TCP reassembly and stream payload extraction (`follow --payload`)
- HTTP request/response parsing (`follow --http`)
- TLS certificate extraction (`get_certificates`)
- IPv6 extension header chains, fragmentation reassembly
- TCP options parsing (MSS, window scale, SACK, timestamps)
- DNS rich record decoding (CNAME chains, authority/additional sections, EDNS, DNSSEC)
- TLS beyond handshake metadata (certificates, session tickets, encrypted extensions)
- Broad protocol identification (3,000+ protocols)

**The seam:** Native runs per-packet in tight loops during pipeline iteration. tshark runs per-stream or per-capture on demand. Native produces typed data structures. tshark produces normalized summaries or raw payloads. Both share the same CLI and MCP surfaces through the backend abstraction.
