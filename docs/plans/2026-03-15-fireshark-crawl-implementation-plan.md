# Fireshark Crawl Phase Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `crawl` phase of Fireshark: a Rust workspace with a reusable packet-analysis core that can read `pcap` and `pcapng` files, decode Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP traffic, and expose a minimal CLI summary command.

**Architecture:** Use a Cargo workspace with strict layering. `fireshark-file` converts capture files into raw frames, `fireshark-dissectors` decodes protocol layers into `fireshark-core` types, and `fireshark-cli` is only a thin harness for exercising the library. Keep live capture, reassembly, and textual display filters out of scope for this phase.

**Tech Stack:** Rust 1.93, Cargo workspace, `thiserror`, `clap`, `nom` or equivalent explicit byte parsing utilities for dissectors, a stable capture-file reader crate for `pcap`/`pcapng` behind the `fireshark-file` API, fixture captures, and standard `cargo test` / `cargo fmt` / `cargo clippy` verification.

---

## Phase Scope

Implement only the `crawl` phase in this plan.

Future phases:

- `walk`: live capture backend plus typed filter/query APIs
- `run`: analyst-facing workflows, display filters, follow-stream, and basic statistics

Do not create speculative code for `walk` or `run` during `crawl` beyond tiny extension seams that are already justified by the `crawl` code.

### Task 1: Initialize Repository And Workspace

**Files:**
- Create: `.gitignore`
- Create: `Cargo.toml`
- Create: `crates/fireshark-core/Cargo.toml`
- Create: `crates/fireshark-core/src/lib.rs`
- Create: `crates/fireshark-dissectors/Cargo.toml`
- Create: `crates/fireshark-dissectors/src/lib.rs`
- Create: `crates/fireshark-file/Cargo.toml`
- Create: `crates/fireshark-file/src/lib.rs`
- Create: `crates/fireshark-cli/Cargo.toml`
- Create: `crates/fireshark-cli/src/main.rs`
- Create: `fixtures/.gitkeep`

**Step 1: Initialize git before any commit-based workflow**

Run: `git init`
Expected: repository initialized in `/Users/hendrik/Desktop/fireshark/.git`

**Step 2: Prove the workspace does not exist yet**

Run: `cargo metadata --format-version 1`
Expected: FAIL with a message about missing `Cargo.toml`

**Step 3: Create the top-level workspace manifest**

```toml
[workspace]
members = [
    "crates/fireshark-core",
    "crates/fireshark-dissectors",
    "crates/fireshark-file",
    "crates/fireshark-cli",
]
resolver = "2"
```

**Step 4: Create the member crates with minimal stubs**

```rust
// crates/fireshark-core/src/lib.rs
pub fn version() -> &'static str {
    "0.1.0"
}
```

```rust
// crates/fireshark-cli/src/main.rs
fn main() {
    println!("fireshark");
}
```

**Step 5: Verify the workspace now resolves**

Run: `cargo metadata --format-version 1 > /tmp/fireshark-metadata.json`
Expected: PASS and writes workspace metadata

**Step 6: Commit**

```bash
git add .gitignore Cargo.toml crates fixtures
git commit -m "chore: initialize fireshark workspace"
```

### Task 2: Define Core Packet Types

**Files:**
- Modify: `crates/fireshark-core/Cargo.toml`
- Modify: `crates/fireshark-core/src/lib.rs`
- Create: `crates/fireshark-core/src/frame.rs`
- Create: `crates/fireshark-core/src/packet.rs`
- Create: `crates/fireshark-core/src/layer.rs`
- Create: `crates/fireshark-core/src/endpoint.rs`
- Create: `crates/fireshark-core/src/issues.rs`
- Create: `crates/fireshark-core/tests/packet_model.rs`

**Step 1: Write the failing model test**

```rust
use fireshark_core::{DecodeIssue, Layer, Packet};

#[test]
fn packet_can_hold_layers_and_issues() {
    let packet = Packet::new(vec![Layer::Unknown], vec![DecodeIssue::truncated(14)]);
    assert_eq!(packet.layers().len(), 1);
    assert_eq!(packet.issues().len(), 1);
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-core packet_can_hold_layers_and_issues -- --exact`
Expected: FAIL with unresolved items such as `Packet` or `DecodeIssue`

**Step 3: Implement the minimal domain model**

```rust
pub enum Layer {
    Unknown,
}

pub struct Packet {
    layers: Vec<Layer>,
    issues: Vec<DecodeIssue>,
}
```

**Step 4: Run the test to verify it passes**

Run: `cargo test -p fireshark-core packet_can_hold_layers_and_issues -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-core
git commit -m "feat: add core packet model"
```

### Task 3: Add Raw Frame Types And Summary Surface

**Files:**
- Modify: `crates/fireshark-core/src/lib.rs`
- Create: `crates/fireshark-core/src/summary.rs`
- Modify: `crates/fireshark-core/src/frame.rs`
- Create: `crates/fireshark-core/tests/frame_summary.rs`

**Step 1: Write the failing summary test**

```rust
use fireshark_core::{Frame, PacketSummary};

#[test]
fn summary_includes_protocol_and_length() {
    let frame = Frame::builder().captured_len(60).protocol("TCP").build();
    let summary = PacketSummary::from(&frame);
    assert_eq!(summary.protocol, "TCP");
    assert_eq!(summary.length, 60);
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-core summary_includes_protocol_and_length -- --exact`
Expected: FAIL because `Frame::builder` or `PacketSummary` do not exist

**Step 3: Implement the minimal frame and summary types**

```rust
pub struct PacketSummary {
    pub protocol: String,
    pub length: usize,
}
```

**Step 4: Run the test to verify it passes**

Run: `cargo test -p fireshark-core summary_includes_protocol_and_length -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-core
git commit -m "feat: add frame summaries"
```

### Task 4: Add Capture-File Reader API And Fixture Tests

**Files:**
- Modify: `crates/fireshark-file/Cargo.toml`
- Modify: `crates/fireshark-file/src/lib.rs`
- Create: `crates/fireshark-file/src/error.rs`
- Create: `crates/fireshark-file/src/reader.rs`
- Create: `crates/fireshark-file/tests/read_pcap.rs`
- Create: `crates/fireshark-file/tests/read_pcapng.rs`
- Create: `fixtures/smoke/minimal.pcap`
- Create: `fixtures/smoke/minimal.pcapng`

**Step 1: Add tiny fixture captures**

Create one packet fixture for `pcap` and one for `pcapng`. Keep them under 2 KB and document their origin in a later fixture README.

**Step 2: Write the failing file-reader tests**

```rust
use fireshark_file::CaptureReader;

#[test]
fn reads_single_packet_from_pcap() {
    let frames = CaptureReader::open("fixtures/smoke/minimal.pcap")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(frames.len(), 1);
}
```

**Step 3: Run the tests to verify they fail**

Run: `cargo test -p fireshark-file reads_single_packet_from_pcap -- --exact`
Expected: FAIL because `CaptureReader` does not exist

**Step 4: Implement the reader behind a small Fireshark-owned API**

```rust
pub struct CaptureReader {
    // wrap the chosen pcap/pcapng parser crate here
}
```

The reader API should return `fireshark_core::Frame` values or a file-layer raw frame type that converts directly into them.

**Step 5: Run the file-reader tests**

Run: `cargo test -p fireshark-file`
Expected: PASS for both `pcap` and `pcapng` smoke tests

**Step 6: Commit**

```bash
git add crates/fireshark-file fixtures
git commit -m "feat: add capture file reader"
```

### Task 5: Implement Ethernet And Network-Layer Dissection

**Files:**
- Modify: `crates/fireshark-dissectors/Cargo.toml`
- Modify: `crates/fireshark-dissectors/src/lib.rs`
- Create: `crates/fireshark-dissectors/src/ethernet.rs`
- Create: `crates/fireshark-dissectors/src/arp.rs`
- Create: `crates/fireshark-dissectors/src/ipv4.rs`
- Create: `crates/fireshark-dissectors/src/ipv6.rs`
- Create: `crates/fireshark-dissectors/tests/ethernet_ipv4.rs`
- Create: `crates/fireshark-dissectors/tests/ethernet_arp.rs`
- Create: `crates/fireshark-dissectors/tests/ethernet_ipv6.rs`

**Step 1: Write the failing Ethernet/IPv4 test**

```rust
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_ethernet_ipv4_layers() {
    let bytes = include_bytes!("../../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();
    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(packet.layer_names().contains(&"IPv4"));
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-dissectors decodes_ethernet_ipv4_layers -- --exact`
Expected: FAIL because `decode_packet` and the layer types do not exist

**Step 3: Implement Ethernet, ARP, IPv4, and IPv6 parsers**

Use explicit parsing and attach `DecodeIssue` values when headers are truncated or malformed.

**Step 4: Run the dissector tests**

Run: `cargo test -p fireshark-dissectors`
Expected: PASS for Ethernet, ARP, IPv4, and IPv6 cases

**Step 5: Commit**

```bash
git add crates/fireshark-dissectors fixtures
git commit -m "feat: add ethernet and network layer dissectors"
```

### Task 6: Implement Transport-Layer Dissection And Packet Summaries

**Files:**
- Modify: `crates/fireshark-dissectors/src/lib.rs`
- Create: `crates/fireshark-dissectors/src/tcp.rs`
- Create: `crates/fireshark-dissectors/src/udp.rs`
- Create: `crates/fireshark-dissectors/src/icmp.rs`
- Modify: `crates/fireshark-core/src/summary.rs`
- Create: `crates/fireshark-dissectors/tests/transport.rs`
- Create: `crates/fireshark-core/tests/summary_render.rs`

**Step 1: Write the failing transport decode test**

```rust
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_tcp_ports() {
    let bytes = include_bytes!("../../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();
    assert_eq!(packet.transport_ports(), Some((443, 51514)));
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-dissectors decodes_tcp_ports -- --exact`
Expected: FAIL because TCP parsing and port accessors are missing

**Step 3: Implement TCP, UDP, and ICMP decoding plus summary extraction**

```rust
pub fn transport_ports(&self) -> Option<(u16, u16)> {
    // return ports when the decoded packet has TCP or UDP
}
```

**Step 4: Run the core and dissector tests**

Run: `cargo test -p fireshark-core -p fireshark-dissectors`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-core crates/fireshark-dissectors
git commit -m "feat: add transport dissectors and summaries"
```

### Task 7: Build The End-To-End Decode Pipeline

**Files:**
- Modify: `crates/fireshark-core/src/lib.rs`
- Modify: `crates/fireshark-file/src/lib.rs`
- Modify: `crates/fireshark-dissectors/src/lib.rs`
- Create: `crates/fireshark-core/src/pipeline.rs`
- Create: `crates/fireshark-core/tests/pipeline.rs`

**Step 1: Write the failing pipeline test**

```rust
use fireshark_core::Pipeline;

#[test]
fn pipeline_decodes_frames_from_reader() {
    let packets = Pipeline::from_path("fixtures/smoke/minimal.pcap")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(packets.len(), 1);
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-core pipeline_decodes_frames_from_reader -- --exact`
Expected: FAIL because `Pipeline` does not exist

**Step 3: Implement the smallest end-to-end decoding pipeline**

The pipeline should connect file reading and protocol dissection while preserving `DecodeIssue` entries instead of dropping malformed packets on the floor.

**Step 4: Run the test to verify it passes**

Run: `cargo test -p fireshark-core pipeline_decodes_frames_from_reader -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-core crates/fireshark-file crates/fireshark-dissectors
git commit -m "feat: add end-to-end decode pipeline"
```

### Task 8: Add A Minimal CLI Summary Command

**Files:**
- Modify: `crates/fireshark-cli/Cargo.toml`
- Modify: `crates/fireshark-cli/src/main.rs`
- Create: `crates/fireshark-cli/src/summary.rs`
- Create: `crates/fireshark-cli/tests/summary_command.rs`

**Step 1: Write the failing CLI integration test**

```rust
#[test]
fn summary_command_prints_one_packet_row() {
    let mut cmd = assert_cmd::Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg("fixtures/smoke/minimal.pcap");
    cmd.assert().success().stdout(predicates::str::contains("TCP"));
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-cli summary_command_prints_one_packet_row -- --exact`
Expected: FAIL because the `summary` command does not exist

**Step 3: Implement the CLI command**

```rust
#[derive(clap::Subcommand)]
enum Command {
    Summary { path: std::path::PathBuf },
}
```

**Step 4: Run the CLI tests**

Run: `cargo test -p fireshark-cli`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-cli
git commit -m "feat: add summary cli"
```

### Task 9: Add Fixtures, Golden Output, And Developer Documentation

**Files:**
- Create: `fixtures/README.md`
- Create: `fixtures/bytes/ethernet_ipv4_tcp.bin`
- Create: `fixtures/bytes/ethernet_ipv4_udp.bin`
- Create: `fixtures/bytes/ethernet_arp.bin`
- Create: `fixtures/bytes/ethernet_ipv6_icmp.bin`
- Create: `README.md`

**Step 1: Document every fixture**

For each fixture, note the protocol stack, expected packet summary, and whether the bytes were handcrafted or derived from a capture.

**Step 2: Add at least one golden-output example to the README**

```text
$ cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap
1  2026-03-15T00:00:00Z  TCP  192.0.2.10:51514 -> 198.51.100.20:443  60
```

**Step 3: Run the full test suite**

Run: `cargo test --workspace`
Expected: PASS

**Step 4: Commit**

```bash
git add fixtures README.md
git commit -m "docs: add fixtures and crawl usage notes"
```

### Task 10: Run Full Verification Before Declaring Crawl Complete

**Files:**
- No file edits required unless verification reveals issues

**Step 1: Format the workspace**

Run: `cargo fmt --all`
Expected: PASS with no diff after rerun

**Step 2: Lint the workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS

**Step 3: Run the full test suite again**

Run: `cargo test --workspace`
Expected: PASS

**Step 4: Review the diff before the final phase-complete commit**

Run: `git status --short`
Expected: clean working tree or only intentionally staged changes

**Step 5: Commit**

```bash
git add .
git commit -m "feat: complete crawl phase"
```

## Walk And Run Follow-On Notes

When `crawl` is complete and stable, create a fresh plan for `walk`. That plan should start by introducing a live-capture trait around the existing decode pipeline rather than replacing it. The `run` phase should not begin until `walk` has proven the packet model and flow identities under real traffic.
