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
- `just` available on your path

Run the summary command against the smoke fixture:

```bash
just summary
```

Example output:

```text
   1  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

Cargo equivalent:

```bash
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
```

## macOS CLI Examples (`pcap` / `pcapng`)

### 1) Record traffic on macOS and save to capture files

List available interfaces first:

```bash
tcpdump -D
```

Record traffic with `tcpdump` (writes **pcap**):

```bash
sudo tcpdump -i en0 -s 0 -w ~/captures/session.pcap
```

- `-i en0`: capture from interface `en0` (replace with yours).
- `-s 0`: capture full packets instead of truncating snapshots.
- `-w ...`: write binary capture output to disk.

Stop capture with `Ctrl+C`.

If you want **pcapng** output directly, use Wireshark's CLI capture tool `dumpcap`:

```bash
/Applications/Wireshark.app/Contents/MacOS/dumpcap -i en0 -w ~/captures/session.pcapng
```

Convert between formats (optional) with `editcap`:

```bash
# pcap -> pcapng
/Applications/Wireshark.app/Contents/MacOS/editcap -F pcapng ~/captures/session.pcap ~/captures/session-converted.pcapng

# pcapng -> pcap
/Applications/Wireshark.app/Contents/MacOS/editcap -F pcap ~/captures/session.pcapng ~/captures/session-converted.pcap
```

### 2) Read `.pcap` and `.pcapng` with Fireshark CLI

After building, Fireshark exposes a CLI named `fireshark` with a `summary` subcommand.

Build once:

```bash
cargo build -p fireshark-cli
```

Run against a `.pcap` file:

```bash
./target/debug/fireshark summary ~/captures/session.pcap
```

Run against a `.pcapng` file:

```bash
./target/debug/fireshark summary ~/captures/session.pcapng
```

Sample output shape:

```text
   1  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
   2  UDP    203.0.113.5:5353       -> 224.0.0.251:5353         76
```

Packets without IPv4/IPv6 endpoints leave the `source` and `destination`
columns blank, so the examples below trim Fireshark's fixed-width columns
instead of assuming every row has the same whitespace-separated fields.

### 3) Summarize Fireshark CLI output with macOS shell tools

Save a packet summary to a file:

```bash
./target/debug/fireshark summary ~/captures/session.pcapng > /tmp/fireshark-summary.txt
```

Count packets by protocol:

```bash
awk '{
  protocol = substr($0, 7, 5)
  gsub(/^ +| +$/, "", protocol)
  if (protocol != "") print protocol
}' /tmp/fireshark-summary.txt | sort | uniq -c | sort -nr
```

Top source endpoints:

```bash
awk '{
  source = substr($0, 14, 22)
  gsub(/^ +| +$/, "", source)
  if (source != "") print source
}' /tmp/fireshark-summary.txt | sort | uniq -c | sort -nr | head
```

Top destination endpoints:

```bash
awk '{
  destination = substr($0, 40, 22)
  gsub(/^ +| +$/, "", destination)
  if (destination != "") print destination
}' /tmp/fireshark-summary.txt | sort | uniq -c | sort -nr | head
```

Largest packets in the capture (by length column):

```bash
awk '{print $NF "\t" $0}' /tmp/fireshark-summary.txt | sort -nr -k1,1 | cut -f2- | head
```

## Development

Run the full local verification pass:

```bash
just check
```

Run formatting:

```bash
just fmt
```

Run linting:

```bash
just clippy
```

Run the full test suite:

```bash
just test
```

Cargo equivalents:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
