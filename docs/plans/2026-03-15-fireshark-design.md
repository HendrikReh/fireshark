# Fireshark Design

**Date:** 2026-03-15

**Goal:** Build a Wireshark-like network analysis tool in Rust by progressing through deliberate `crawl`, `walk`, and `run` phases instead of attempting a feature-complete clone from the start.

## Decisions

- Optimize for a reusable core library first.
- Make `crawl` an offline capture-file phase, not a live-capture phase.
- Support `pcap` and `pcapng` in `crawl`.
- Decode Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP in `crawl`.
- Design for cross-platform live capture later, but do not implement it in `crawl`.
- Define `run` by analyst workflows such as packet lists, display filters, follow-stream, and basic statistics rather than by protocol-count growth alone.

## Recommended Approach

Use a library-first vertical-slice architecture.

This approach creates a stable packet-analysis core before introducing live capture or a GUI. Each phase adds one end-to-end capability:

- `crawl`: offline file reading and decoding
- `walk`: live capture and basic queryability
- `run`: analyst-facing workflows

This was chosen over a full multi-crate skeleton with placeholders and over a protocol-lab-first approach because it keeps abstractions honest and reduces speculative design.

## Architecture

The project should be a Rust workspace with clear crate boundaries:

- `fireshark-core`
  Canonical domain types such as `Frame`, `Packet`, `Layer`, `Endpoint`, `DecodeIssue`, timestamps, and summary data.
- `fireshark-file`
  Capture-file ingestion for `pcap` and `pcapng`, yielding raw frames plus capture metadata.
- `fireshark-dissectors`
  Pure protocol decoding from bytes into typed layers.
- `fireshark-capture`
  Trait-only or stub crate in `crawl`; becomes the live-capture seam in `walk`.
- `fireshark-cli`
  Thin development frontend for exercising the library with commands such as `summary <file>`.

## Data Flow

The data flow should stay linear and explicit:

`capture/file source -> raw frame -> decode pipeline -> structured packet -> summary/query APIs`

Important boundaries:

- File-format parsing must stay separate from protocol dissection.
- Dissection should support partial success and preserve undecoded bytes when needed.
- Public APIs should prefer iteration and streaming over loading an entire capture into memory.

## Phase Plan

### Crawl

Build the smallest useful offline analysis stack:

- Open `pcap` and `pcapng`
- Iterate frames with timestamps, lengths, and raw bytes
- Decode Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP
- Produce packet summaries with addresses, protocol, ports, and length
- Add fixture captures and golden tests
- Provide a minimal CLI summary command

Explicitly out of scope:

- Live capture
- GUI
- Full display-filter language
- Reassembly
- Follow-stream
- Advanced statistics

### Walk

Add one real live-capture backend without changing the core packet model:

- Introduce a capture trait and one backend
- Feed live packets into the same decode pipeline
- Add typed filter predicates
- Add conversation and stream identity primitives

### Run

Turn the library into an analyst-usable tool:

- Packet list and detail views in a real frontend
- Display filters
- Follow TCP/UDP stream
- Basic statistics such as protocol counts and top talkers
- Better error surfacing and performance work for larger captures

## Technical Choices

- Prefer explicit byte parsing for protocol dissectors so errors and offsets stay visible.
- Keep owned domain objects at public API boundaries.
- Model decode failures as structured issues with severity and byte-offset context.
- Add typed filter predicates before introducing a textual filter language.
- Introduce packet and flow identity types early so later stream analysis does not force a redesign.

## Risks To Avoid

- Overbuilding abstractions before real packets exercise them
- Mixing file parsing with protocol decoding
- Designing around a future GUI too early
- Chasing protocol breadth before useful workflows exist

## Testing Strategy

- `crawl`: parser unit tests, dissector unit tests, fixture-based golden tests
- `walk`: backend integration tests plus synthetic packet injection
- `run`: end-to-end workflow tests around filtering, summaries, and stream grouping

## Current Repository Note

The working directory was empty and was not initialized as a git repository when this design was written. The design document can be saved immediately, but it cannot be committed until git is initialized.
