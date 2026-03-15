# Fireshark

Fireshark is a Wireshark-inspired packet analyzer written in Rust and built in deliberate phases instead of as a "boil the ocean" clone.

The project is intentionally library-first. The early goal is to build a clean capture and decode core that can support multiple frontends later, rather than jumping straight into a full desktop UI.

## Status

Fireshark is currently in the `crawl` phase.

What works today:

- read `pcap` and `pcapng` capture files
- decode Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP
- build structured packets through a reusable decode pipeline
- print packet summaries through a minimal CLI
- validate behavior with fixture-based tests

What does not exist yet:

- live packet capture
- GUI or TUI packet inspection
- display filter language
- stream following or reassembly
- advanced statistics

## Why Phases

The project is split into three phases so the architecture hardens around real packet data before the surface area grows:

- `crawl`
  Offline capture parsing, foundational protocol dissection, and a minimal CLI
- `walk`
  Live capture backends, typed filtering primitives, and conversation identity
- `run`
  Analyst-facing workflows such as packet views, display filters, follow-stream, and statistics

This keeps early work small, testable, and hard to overengineer.

## Workspace Layout

- `crates/fireshark-core`
  Core domain types, summaries, and the generic decode pipeline
- `crates/fireshark-file`
  `pcap` and `pcapng` ingestion
- `crates/fireshark-dissectors`
  Protocol decoding for Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP
- `crates/fireshark-cli`
  Thin CLI for exercising the library stack
- `fixtures/`
  Handcrafted binary fixtures used by the test suite
- `docs/plans/`
  Phase design and implementation planning documents

## Quick Start

Requirements:

- Rust toolchain installed
- `cargo` available on your path

Run the summary command against the smoke fixture:

```bash
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
```

Example output:

```text
   1  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

## Development

Run the full test suite:

```bash
cargo test --workspace
```

Run formatting:

```bash
cargo fmt --all
```

Run linting:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

## Design Direction

Fireshark is being built around a stable packet-analysis core, not around a specific frontend.

Current design rules:

- file parsing stays separate from protocol dissection
- decoding favors explicit, typed layers over ad hoc byte inspection
- APIs should support streaming/iteration instead of forcing full-file loading
- features are added in vertical slices, not as large speculative frameworks

## Roadmap

### Crawl

- support offline `pcap` and `pcapng`
- establish the packet model and decode pipeline
- prove the architecture with a minimal CLI

### Walk

- add a live capture abstraction and one real backend
- introduce typed filter/query APIs
- start conversation and stream identity primitives

### Run

- build real analysis workflows
- add richer packet inspection UX
- support display filtering, follow-stream, and basic statistics

## Repository Notes

This repository is public but still early-stage. The current implementation is intentionally narrow: correctness, layering, and testability matter more than protocol breadth at this stage.
