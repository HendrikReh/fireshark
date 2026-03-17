# Developer Guide

This guide covers everything a contributor needs to build, test, and extend Fireshark. After reading it you should be able to add a new protocol dissector end-to-end.

---

## 1. Getting Started

### Prerequisites

| Tool | Purpose |
|---|---|
| **Rust toolchain** (edition 2024) | `rustup` will handle this; the workspace `Cargo.toml` declares `edition = "2024"` |
| **cargo** | Comes with Rust |
| **just** | Task runner -- install via `cargo install just` or your OS package manager |
| **cargo-fuzz** (optional) | For fuzzing targets -- `cargo install cargo-fuzz` |

### Clone and build

```bash
git clone <repo-url> fireshark
cd fireshark
cargo build --workspace
```

### Run the full gate

```bash
just check   # runs fmt-check, clippy, and all tests in sequence
```

This is the single command that must pass before any work is considered complete.

### First run

```bash
# One-line packet summary listing
cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap

# Detail view for packet 1 (layer tree + color hex dump)
cargo run -p fireshark-cli -- detail fixtures/smoke/minimal.pcap 1

# With a display filter
cargo run -p fireshark-cli -- summary fixtures/smoke/fuzz-2006-06-26-2594.pcap -f "tcp and port 80"
```

### Available just recipes

| Recipe | What it does |
|---|---|
| `just check` | `fmt-check` + `clippy` + `test` (the CI gate) |
| `just test` | `cargo test --workspace` |
| `just clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `just fmt` | `cargo fmt --all` |
| `just fmt-check` | `cargo fmt --all -- --check` |
| `just summary [file]` | Quick run of the summary command (defaults to `fixtures/smoke/minimal.pcap`) |

---

## 2. Code Conventions

### Rust edition and tooling

- **Edition 2024** -- declared in the workspace `Cargo.toml`.
- Clippy runs with **`-D warnings`** -- every warning is a build-breaking error. Fix them, do not suppress them.
- Formatting is checked by `cargo fmt --all -- --check`. Run `just fmt` before committing.

### Error handling

- Errors use **`thiserror`** derive macros. Dissectors use `DecodeError`; file readers use `CaptureError`.
- **Never** use `unwrap()` or `expect()` on data derived from untrusted packet input. Any byte slice from a capture file is untrusted.
- Dissectors return `Result<T, DecodeError>` where `T` is either `Layer` (transport-level) or `NetworkPayload` (network-level).

### Naming

- Protocol constants live at the top of each dissector module: `ETHER_TYPE`, `IP_PROTOCOL`, `MIN_HEADER_LEN`.
- Layer types are plain structs with public fields, defined in `fireshark-core::layer`.
- The `Layer` enum in core wraps each protocol's typed layer struct.

### Testing

- Use **fixture files** (`fixtures/bytes/`, `fixtures/smoke/`) rather than constructing raw bytes inline.
- CLI integration tests use `assert_cmd` and `predicates`.
- Issue tracking uses **bd** (beads) -- do not use markdown TODOs.

---

## 3. Project Structure

### Workspace layout

```
fireshark/
  Cargo.toml              # Workspace root (version 0.5.1, edition 2024)
  Justfile                # Task runner recipes
  CLAUDE.md               # AI agent conventions
  crates/
    fireshark-core/       # Domain types: Layer, Packet, Frame, Pipeline, StreamTracker, TrackingPipeline, PacketSummary
    fireshark-dissectors/  # Protocol decoders: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS (10 protocols)
    fireshark-file/       # pcap and pcapng file ingestion (CaptureReader)
    fireshark-filter/     # Display filter parser and evaluator (including tcp.stream/udp.stream)
    fireshark-cli/        # CLI binary ("fireshark") with 6 commands: summary, detail, stats, issues, audit, follow
    fireshark-mcp/        # MCP server binary (17 tools) for LLM-driven capture analysis
  fixtures/
    bytes/                # Handcrafted binary blobs for unit tests
    smoke/                # Small pcap/pcapng files for integration tests
  fuzz/
    fuzz_targets/         # cargo-fuzz targets (decode_packet, capture_reader)
  docs/
    plans/                # Phase design documents
    stakeholders/         # Audience-specific docs (you are here)
```

### Crate dependency graph

```
fireshark-cli ──┬── fireshark-dissectors ── fireshark-core
                ├── fireshark-file ──────── fireshark-core
                ├── fireshark-filter ────── fireshark-core
                └── fireshark-core

fireshark-mcp ──┬── fireshark-dissectors
                ├── fireshark-file
                ├── fireshark-filter
                └── fireshark-core
```

Key rule: **MCP types stay in `fireshark-mcp`** -- no serde/schemars/MCP leakage into core crates.

### What lives where

| Directory | Contents |
|---|---|
| `fixtures/bytes/` | One binary file per protocol scenario (`ethernet_ipv4_tcp.bin`, `tcp_syn_ack.bin`, `icmp_dest_unreachable.bin`, etc.) |
| `fixtures/smoke/` | Small full captures (`minimal.pcap`, `minimal.pcapng`, `fuzz-2006-06-26-2594.pcap`) |
| `fuzz/fuzz_targets/` | Two fuzz harnesses: `fuzz_decode_packet.rs` (raw bytes through dissector chain) and `fuzz_capture_reader.rs` (arbitrary bytes as pcap file) |
| `docs/plans/` | Phase design documents |

---

## 4. How to Add a New Protocol Dissector

This walkthrough uses DNS as an example. You will touch six crates.

### Step 1: Add the layer type to `fireshark-core`

Edit `crates/fireshark-core/src/layer.rs`:

```rust
// Add the typed layer struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLayer {
    pub transaction_id: u16,
    pub is_response: bool,
    pub question_count: u16,
    pub answer_count: u16,
}

// Add a variant to the Layer enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    // ... existing variants ...
    Dns(DnsLayer),
}

// Add a branch to Layer::name()
impl Layer {
    pub fn name(&self) -> &'static str {
        match self {
            // ... existing arms ...
            Self::Dns(_) => "DNS",
        }
    }
}
```

Export the new type in `crates/fireshark-core/src/lib.rs`:

```rust
pub use layer::{
    // ... existing exports ...
    DnsLayer,
};
```

### Step 2: Create the dissector module

Create `crates/fireshark-dissectors/src/dns.rs`:

```rust
use fireshark_core::{DnsLayer, Layer};
use crate::DecodeError;

/// DNS is carried over UDP port 53 (and sometimes TCP).
/// For the dissector chain, DNS is an application-layer protocol.
pub const UDP_PORT: u16 = 53;
const MIN_HEADER_LEN: usize = 12;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "DNS",
            offset: offset + bytes.len(),
        });
    }

    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = (flags & 0x8000) != 0;

    Ok(Layer::Dns(DnsLayer {
        transaction_id: u16::from_be_bytes([bytes[0], bytes[1]]),
        is_response,
        question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
        answer_count: u16::from_be_bytes([bytes[6], bytes[7]]),
    }))
}
```

Key rules for the `parse` function:
1. **Bounds-check before every slice access.** Always check `bytes.len() < MIN_HEADER_LEN` first.
2. Return `DecodeError::Truncated` for short buffers with the byte offset where truncation was detected.
3. Return `DecodeError::Malformed` for structurally invalid fields.
4. Never use `unwrap()` or `expect()` on anything derived from `bytes`.

### Step 3: Wire it into the decode pipeline

Edit `crates/fireshark-dissectors/src/lib.rs`:

```rust
mod dns;  // Add module declaration

// In decode_packet(), after transport-layer dispatch, add application-layer dispatch.
// DNS runs on top of UDP, so check port 53 after the UDP layer is decoded.
```

For application-layer protocols, fireshark supports two dispatch strategies:

1. **Port-based dispatch** (e.g., DNS on UDP port 53): Inside the UDP handling path in `decode_packet()`, after the UDP layer has been decoded and added to the packet, check if either source or destination port matches the application-layer protocol's well-known port.

2. **Heuristic dispatch** (e.g., TLS on any TCP port): Inside the TCP handling path, after the TCP layer has been decoded, inspect the payload bytes for protocol-specific magic bytes. TLS is detected by checking for the record header signature (`0x16 0x03 0x0X` where X <= 3, plus handshake type byte at offset 5). This allows TLS detection on any TCP port, not just 443.

Choose port-based dispatch when the protocol has a well-known port, and heuristic dispatch when the protocol can appear on any port or when port-based detection is insufficient.

### Step 4: Create test fixtures

Create a binary fixture at `fixtures/bytes/ethernet_ipv4_udp_dns_query.bin`. This is a raw Ethernet frame containing a real DNS query.

The simplest approach: capture a DNS query with `tcpdump -c 1 -w dns.pcap port 53`, then extract the raw frame bytes. Alternatively, construct the bytes by hand following the protocol spec.

### Step 5: Add unit tests

Add tests to `crates/fireshark-dissectors/src/dns.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_query() {
        let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns_query.bin");
        // Skip Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes to reach DNS payload
        let dns_payload = &bytes[42..];
        let layer = parse(dns_payload, 42).unwrap();
        match layer {
            Layer::Dns(dns) => {
                assert!(!dns.is_response);
                assert!(dns.question_count >= 1);
            }
            _ => panic!("expected DNS layer"),
        }
    }

    #[test]
    fn rejects_truncated_dns() {
        let short = [0u8; 6];
        let err = parse(&short, 42).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { .. }));
    }
}
```

### Step 6: Update the summary module

Edit `crates/fireshark-core/src/summary.rs` -- the `PacketSummary::from_packet` function determines the top-level protocol name. The existing logic already picks the last non-Ethernet/non-Unknown layer, so `Layer::Dns(_)` will naturally show `"DNS"` as the protocol via `Layer::name()`. No change needed unless you want special endpoint formatting.

### Step 7: Update CLI detail rendering

Edit `crates/fireshark-cli/src/detail.rs`:

```rust
// Import the new layer type
use fireshark_core::{/* ... existing imports ... */, DnsLayer};

// Add a branch in render_layer()
fn render_layer<W: Write>(w: &mut W, layer: &Layer) -> io::Result<()> {
    match layer {
        // ... existing arms ...
        Layer::Dns(l) => render_dns(w, l),
    }
}

// Add the render function
fn render_dns<W: Write>(w: &mut W, l: &DnsLayer) -> io::Result<()> {
    let qr = if l.is_response { "Response" } else { "Query" };
    writeln!(w, "{}", format!("▸ DNS").color(color::protocol_color("DNS")))?;
    writeln!(w, "    Transaction ID: 0x{:04x}  {}", l.transaction_id, qr)?;
    writeln!(w, "    Questions: {}  Answers: {}", l.question_count, l.answer_count)
}
```

### Step 8: Add a color for the protocol

Edit `crates/fireshark-cli/src/color.rs` -- add a branch in `protocol_color()`:

```rust
pub fn protocol_color(protocol: &str) -> Color {
    // ... existing branches ...
    } else if protocol.eq_ignore_ascii_case("dns") {
        Color::Magenta
    } else {
        Color::Red
    }
}
```

### Step 9: Update the MCP model

Edit `crates/fireshark-mcp/src/model.rs`:

```rust
// Add a variant to LayerView
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum LayerView {
    // ... existing variants ...
    #[serde(rename = "DNS")]
    Dns {
        transaction_id: u16,
        is_response: bool,
        question_count: u16,
        answer_count: u16,
    },
}

// Add a branch in LayerView::from_layer()
impl LayerView {
    pub fn from_layer(layer: &Layer) -> Self {
        match layer {
            // ... existing arms ...
            Layer::Dns(layer) => Self::Dns {
                transaction_id: layer.transaction_id,
                is_response: layer.is_response,
                question_count: layer.question_count,
                answer_count: layer.answer_count,
            },
        }
    }
}
```

### Step 10: Update the filter field registry

Edit `crates/fireshark-filter/src/evaluate.rs` -- add DNS fields to `resolve_layer_field()`:

```rust
fn resolve_layer_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    for layer in decoded.packet().layers() {
        match (field, layer) {
            // ... existing arms ...

            // DNS
            ("dns.id", Layer::Dns(l)) => return Some(FieldValue::Integer(u64::from(l.transaction_id))),
            ("dns.qr", Layer::Dns(l)) => return Some(FieldValue::Bool(l.is_response)),
            ("dns.count.queries", Layer::Dns(l)) => return Some(FieldValue::Integer(u64::from(l.question_count))),
            ("dns.count.answers", Layer::Dns(l)) => return Some(FieldValue::Integer(u64::from(l.answer_count))),

            _ => {}
        }
    }
    None
}
```

Also add DNS to the `has_protocol` function and the `Protocol` enum in `crates/fireshark-filter/src/ast.rs`.

### Step 11: Run the gate

```bash
just check
```

Fix any clippy warnings, formatting issues, or test failures before considering the work done.

---

## 5. Native Dissector vs tshark: When to Use Which

Fireshark has two analysis backends: a native Rust pipeline and an optional tshark subprocess. As a developer, you need to decide when a protocol requires a native dissector and when tshark coverage is sufficient.

### Add a native dissector when:

- **The protocol needs typed fields for audit heuristics.** The security audit engine (`fireshark-mcp/src/audit.rs`) pattern-matches on typed `Layer` fields. For example, scan detection inspects `TcpLayer.flags`, and DNS tunneling detection inspects `DnsLayer` payload sizes. If your protocol has security-relevant patterns, those patterns need typed fields to be detectable.
- **The protocol needs typed fields for filter evaluation.** The display filter evaluator (`fireshark-filter/src/evaluate.rs`) resolves field names like `tcp.flags.syn` against concrete `Layer` variants. If users need to filter on specific fields of your protocol, those fields must exist as struct members.
- **The protocol needs typed fields for MCP tool results.** The MCP server returns structured JSON with per-field data (`LayerView` in `fireshark-mcp/src/model.rs`). An LLM client expects typed, named fields -- not opaque strings.
- **The protocol participates in stream tracking.** `StreamTracker` extracts 5-tuples from typed `Ipv4Layer`/`Ipv6Layer` + `TcpLayer`/`UdpLayer` fields. Any protocol that needs conversation tracking must have native layers.
- **The protocol needs per-layer byte spans for hex dump coloring.** `LayerSpan` records are produced during native dissection. tshark cannot provide this data.

### Rely on tshark when:

- **You only need protocol identification for summary/stats.** If the goal is to show "this packet is HTTP/2" in a summary line and count it in protocol statistics, the tshark backend already provides protocol names without needing a native dissector.
- **You need broad protocol coverage for triage.** When analyzing a capture with many unfamiliar protocols, `--backend tshark` gives immediate visibility into what protocols are present.
- **You are doing differential testing.** tshark serves as a correctness oracle. Compare native dissector output against tshark output to validate field extraction.

### The BackendCapture abstraction

The `BackendCapture` trait in `fireshark-backend` provides a common interface for both backends. CLI commands (`summary`, `stats`) and MCP tools that only need `PacketSummary` data work with either backend transparently. Commands that require full `DecodedFrame` access (`detail`, `follow`, `audit`, `issues`) require the native backend and will return an error if invoked with `--backend tshark`.

This means: when you add a new CLI command or MCP tool, decide whether it needs typed layer access or just summary-level data. If summary-level, wire it through `BackendCapture` so it works with both backends. If it needs typed layers, require the native backend.

## 6. How to Add a New Filter Field

The filter system works in three layers: **lexer** (tokenizes the string), **parser** (builds an AST), and **evaluator** (resolves fields against decoded frames).

### Adding a field to an existing protocol

If you are adding a new field for an already-supported protocol (e.g., `tcp.checksum`), you only need to edit one function.

Edit `crates/fireshark-filter/src/evaluate.rs`, inside `resolve_layer_field()`:

```rust
("tcp.checksum", Layer::Tcp(l)) => {
    return Some(FieldValue::Integer(u64::from(l.checksum)));
}
```

The match pattern is `(field_name_string, Layer::Variant(l))`. The field name string (e.g., `"tcp.checksum"`) is what users type in filter expressions.

Return types:
- `FieldValue::Integer(u64)` -- for numeric fields (ports, lengths, counters, flags as integers)
- `FieldValue::Address(IpAddr)` -- for IP address fields (supports `==`, `!=`, CIDR matching)
- `FieldValue::Bool(bool)` -- for boolean fields (supports bare-field truthiness, `== true`/`== false`)
- `FieldValue::PortPair(u16, u16)` -- for dual-port fields like `tcp.port` (matches if either port matches)

### Adding a new protocol to the filter system

If you are adding filter support for a completely new protocol:

1. Add a variant to the `Protocol` enum in `crates/fireshark-filter/src/ast.rs`
2. Add a token and keyword mapping in `crates/fireshark-filter/src/lexer.rs`
3. Add the token-to-protocol mapping in the parser at `crates/fireshark-filter/src/parser.rs`
4. Add the `matches!` arm in `has_protocol()` in `crates/fireshark-filter/src/evaluate.rs`
5. Add field arms in `resolve_layer_field()` as described above

---

## 7. How to Add a New CLI Command

The CLI uses [clap](https://docs.rs/clap) with derive macros. Commands are defined as enum variants.

### Step 1: Add the subcommand variant

Edit `crates/fireshark-cli/src/main.rs`:

```rust
#[derive(Debug, Subcommand)]
enum Command {
    Summary { /* ... */ },
    Detail { /* ... */ },
    // Add your command
    Stats {
        path: PathBuf,
    },
}
```

### Step 2: Create the implementation module

Create `crates/fireshark-cli/src/stats.rs`:

```rust
use std::path::Path;
use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    for decoded in Pipeline::new(reader, decode_packet) {
        let decoded = decoded?;
        // ... your logic ...
    }
    Ok(())
}
```

### Step 3: Wire it up in main

```rust
mod stats;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Summary { path, filter } => summary::run(&path, filter.as_deref())?,
        Command::Detail { path, packet } => detail::run(&path, packet)?,
        Command::Stats { path } => stats::run(&path)?,
    }
    Ok(())
}
```

### Step 4: Add an integration test

Create `crates/fireshark-cli/tests/stats_command.rs`:

```rust
mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn stats_command_runs_successfully() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg(&fixture);
    cmd.assert().success();
}
```

The `support::repo_root()` helper locates the workspace root from `CARGO_MANIFEST_DIR`, so tests work regardless of the working directory.

---

## 8. Testing Guide

### Unit tests

Unit tests live alongside the code they test (in `#[cfg(test)] mod tests` blocks). They cover:

- **Dissector parsing** -- correct field extraction, truncation errors, malformation errors
- **Filter evaluation** -- protocol matching, field comparisons, shorthand keywords, compound expressions
- **Color mapping** -- protocol-to-color assignments
- **Timestamp formatting** -- ISO 8601 output correctness
- **Hex dump rendering** -- layout, colorization, multi-row handling

All dissector tests use `include_bytes!` to load fixtures:

```rust
#[test]
fn parses_tcp_syn() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_syn.bin");
    let layer = parse(bytes, 0).unwrap();
    // ... assertions ...
}
```

### Integration tests

Integration tests live in `crates/fireshark-cli/tests/`. They run the compiled binary via `assert_cmd`:

```rust
let mut cmd = Command::cargo_bin("fireshark").unwrap();
cmd.arg("summary").arg(&fixture);
cmd.assert()
    .success()
    .stdout(contains("TCP"));
```

Current integration test files:
- `summary_command.rs` -- pcap/pcapng summary output
- `detail_command.rs` -- layer tree, hex dump, decode issues
- `filter_command.rs` -- display filter with the summary command
- `follow_command.rs` -- follow stream output
- `stats_command.rs` -- capture statistics output
- `issues_command.rs` -- decode issue listing
- `audit_command.rs` -- security audit output
- `fuzz_regression.rs` -- regression tests from fuzz findings

### Creating fixture files

**Binary fixtures** (`fixtures/bytes/`): raw Ethernet frame bytes. One file per test scenario. Create them by:

1. **Capture real traffic**: `tcpdump -c 1 -w capture.pcap <filter>`, then extract raw frame bytes
2. **Construct by hand**: write the hex bytes directly. For example, a minimal Ethernet + IPv4 + TCP SYN is 54 bytes.

Naming convention: `<link>_<network>_<transport>[_variant].bin`
- `ethernet_ipv4_tcp.bin`
- `ethernet_ipv6_icmp.bin`
- `tcp_syn_ack.bin` (transport-only, for dissector tests that skip lower layers)
- `ipv4_fragment_first.bin`

**Smoke fixtures** (`fixtures/smoke/`): complete pcap or pcapng files with one or more packets. Used for CLI integration tests.

### Fuzz testing

Two fuzz targets exist in `fuzz/fuzz_targets/`:

| Target | What it feeds | Goal |
|---|---|---|
| `fuzz_decode_packet` | Arbitrary bytes as a raw Ethernet frame through `decode_packet()` | No panics on any input |
| `fuzz_capture_reader` | Arbitrary bytes as a pcap file through `CaptureReader` | No panics on any input |

Run fuzz testing:

```bash
# Install cargo-fuzz if not present
cargo install cargo-fuzz

# Run a fuzz target (runs until you Ctrl+C)
cd fuzz
cargo fuzz run fuzz_decode_packet

# Run with a time limit
cargo fuzz run fuzz_decode_packet -- -max_total_time=300
```

If a fuzz target finds a crash, it saves the reproducer in `fuzz/artifacts/`. Add a regression test for it.

### The `just check` workflow

Always run `just check` before considering any work complete. It runs three stages in sequence:

1. **`fmt-check`** -- fails if any file is not formatted
2. **`clippy`** -- fails on any warning (since `-D warnings` is set)
3. **`test`** -- runs all workspace tests

If clippy fails, fix the issue rather than suppressing the lint. If tests fail, investigate before proceeding.

---

## 9. Common Patterns

### The Layer / decode / summary pattern

This is the core data flow:

```
raw bytes ──[dissector]──> Packet (Vec<Layer>) ──[summary]──> PacketSummary
                                                              { protocol, source, destination, length }
```

1. `decode_packet(bytes)` in `fireshark-dissectors` parses an Ethernet frame into a `Packet` containing ordered `Layer` values.
2. `PacketSummary::from_packet()` walks the layers in reverse to find the most-specific protocol name, then extracts IP/port endpoints for display.
3. `Layer::name()` returns the human-readable protocol string used in summaries, detail views, and color mapping.

Each `Layer` variant wraps a typed struct (e.g., `Layer::Tcp(TcpLayer)`). Fields are public for direct access. No getters, no trait-based abstraction.

### The NetworkPayload pattern

Network-layer dissectors (IPv4, IPv6) return `NetworkPayload` instead of `Layer` directly:

```rust
pub(crate) struct NetworkPayload<'a> {
    pub layer: Layer,           // The decoded network layer
    pub protocol: u8,           // Next-header protocol number (6=TCP, 17=UDP, etc.)
    pub payload: &'a [u8],      // Remaining bytes after the network header
    pub payload_offset: usize,  // Byte offset where payload starts in the original frame
    pub issues: Vec<DecodeIssue>,
}
```

This allows `decode_packet()` to chain into transport-layer dispatch based on the `protocol` field. Transport-layer dissectors (TCP, UDP, ICMP) return `Layer` directly since there is no further chaining in the current crawl phase.

### The Frame builder pattern

`Frame` uses a builder to construct instances with optional metadata:

```rust
let frame = Frame::builder()
    .captured_len(packet.data.len())
    .original_len(packet.orig_len as usize)
    .timestamp(packet.timestamp)
    .data(packet.data.into_owned())
    .protocol("UNKNOWN")
    .build();
```

- `captured_len` defaults to `data.len()` if not set
- `original_len` defaults to `captured_len` if not set
- `timestamp` is optional (pcapng SimplePacket blocks may not have one)
- `build()` consumes the builder

### The Pipeline iterator pattern

`Pipeline` is a generic iterator adapter that pairs frame sources with decoder functions:

```rust
pub struct Pipeline<I, D> {
    frames: I,       // Iterator yielding Result<Frame, FrameError>
    decoder: D,      // Fn(&[u8]) -> Result<Packet, DecodeError>
}
```

Usage:

```rust
let reader = CaptureReader::open(path)?;
for result in Pipeline::new(reader, decode_packet) {
    let decoded: DecodedFrame = result?;
    let summary = decoded.summary();
    // ...
}
```

The `Pipeline` adapts any `Iterator<Item = Result<Frame, E>>` -- you can feed it a `CaptureReader`, a `Vec<Result<Frame, ...>>`, or any custom source. The decoder function is a plain `Fn(&[u8]) -> Result<Packet, DecodeError>`, not a trait object.

### The TrackingPipeline / StreamTracker pattern

`TrackingPipeline` wraps `Pipeline` and assigns stream IDs during iteration:

```rust
let reader = CaptureReader::open(path)?;
let mut pipeline = TrackingPipeline::new(reader, decode_packet);

for result in pipeline.by_ref() {
    let decoded: DecodedFrame = result?;
    // decoded.stream_id() is Some(u32) for TCP/UDP, None for ARP/ICMP-only
}

// After iteration, retrieve accumulated stream metadata
let tracker = pipeline.into_tracker();
for meta in tracker.streams() {
    println!("Stream {}: {} packets", meta.id, meta.packet_count);
}
```

`StreamKey` normalizes both directions of a conversation: the "lower" `(addr, port)` pair is always first. This means `(A:80 -> B:12345)` and `(B:12345 -> A:80)` produce the same key. The protocol number (6=TCP, 17=UDP) is part of the key.

Use `TrackingPipeline` when you need stream IDs (follow command, stats with stream count, MCP stream tools). Use plain `Pipeline` when you do not need stream tracking (simple summary listing).

### The color / protocol_color pattern

The `color` module in `fireshark-cli` maps protocol names to ANSI colors (Wireshark-inspired):

| Protocol | Color |
|---|---|
| TCP | Green |
| UDP | Blue |
| ARP | Yellow |
| ICMP | Cyan |
| DNS | Magenta |
| TLS | BrightGreen |
| Ethernet, IPv4, IPv6 | White |
| Unknown / other | Red |

Two functions are exposed:
- `protocol_color(name: &str) -> Color` -- returns the raw `colored::Color` value (case-insensitive)
- `colorize(protocol: &str, line: &str) -> ColoredString` -- colors an entire output line

When adding a new protocol, add a branch to `protocol_color()` before the final `else` clause. The detail renderer uses `protocol_color()` directly for per-layer header coloring; the summary renderer uses `colorize()` for full-line coloring.

### The filter evaluate pattern

The filter evaluator in `crates/fireshark-filter/src/evaluate.rs` resolves field names against decoded frames using a flat match table:

```rust
fn resolve_layer_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    for layer in decoded.packet().layers() {
        match (field, layer) {
            ("ip.src", Layer::Ipv4(l)) => return Some(FieldValue::Address(IpAddr::V4(l.source))),
            ("tcp.srcport", Layer::Tcp(l)) => return Some(FieldValue::Integer(u64::from(l.source_port))),
            // ... all other fields ...
            _ => {}
        }
    }
    None
}
```

This iterates over all layers, matching `(field_string, Layer_variant)` tuples. The first match wins. This pattern is intentionally flat -- no registry trait, no dynamic dispatch. Adding a field means adding one match arm.

### The LayerSpan / hex dump pattern

Each layer tracks its byte range in the original frame via `LayerSpan { offset, len }`. The hex dump renderer uses these spans to colorize bytes by protocol:

```rust
let span_colors: Vec<(LayerSpan, &str)> = decoded
    .packet()
    .layers()
    .iter()
    .zip(decoded.packet().spans())
    .map(|(layer, span)| (*span, layer.name()))
    .collect();
hexdump::render(&mut out, decoded.frame().data(), &span_colors)?;
```

Spans are searched in reverse order so the innermost (most specific) layer wins when spans overlap.

---

**Version:** 0.5.1 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
