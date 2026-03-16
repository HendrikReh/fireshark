# CLAUDE.md

## Project Overview

Fireshark is a Wireshark-inspired packet analyzer written in Rust. It is library-first and built in phases (crawl/walk/run). Currently in the **crawl** phase: offline pcap/pcapng parsing, foundational protocol dissection, and a minimal CLI.

## Workspace Layout

| Crate | Purpose |
|---|---|
| `fireshark-core` | Domain types (`Layer`, `Packet`, `Frame`, `Pipeline`), summaries, decode issues |
| `fireshark-dissectors` | Protocol decoders: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP |
| `fireshark-file` | pcap and pcapng file ingestion |
| `fireshark-cli` | Thin CLI binary (`fireshark`) exercising the library stack |

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

## Dissector Pattern

Each protocol dissector in `fireshark-dissectors/src/` follows this structure:

1. Module-level constants (`ETHER_TYPE`, `IP_PROTOCOL`, `MIN_HEADER_LEN`)
2. A `parse(bytes: &[u8], ...)` function that validates and decodes
3. Explicit bounds checks before every slice access
4. Returns `DecodeError::Truncated` for short buffers, `DecodeError::Malformed` for invalid fields
5. Network-layer dissectors (IPv4, IPv6) return `NetworkPayload` with payload slice and offset
6. Link/transport-layer dissectors return `Layer` directly

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
