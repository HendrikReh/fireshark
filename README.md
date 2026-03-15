# Fireshark

Fireshark is a Wireshark-inspired packet analysis project written in Rust and built in deliberate phases:

- `crawl`
  Offline capture parsing, basic protocol dissection, and a minimal summary CLI
- `walk`
  Live capture backends and typed filtering primitives
- `run`
  Analyst-facing workflows such as display filters, follow-stream, and statistics

The current repository is in the `crawl` phase.

## Workspace

- `crates/fireshark-core`
  Packet/domain model, summaries, and the generic decode pipeline
- `crates/fireshark-file`
  `pcap` and `pcapng` ingestion
- `crates/fireshark-dissectors`
  Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP decoding
- `crates/fireshark-cli`
  Thin CLI for exercising the library stack

## Current Capabilities

- Read `pcap` and `pcapng`
- Decode Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP
- Summarize decoded packets through the CLI
- Run fixture-based tests for file parsing and protocol decoding

## Quick Start

```bash
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
```

Example output:

```text
   1  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

## Phase Notes

The `crawl` phase intentionally avoids live capture, GUI work, stream following, and a textual filter language. Those remain explicit later-phase goals so the early library APIs can harden around real packet data first.
