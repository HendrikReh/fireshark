# Fireshark Testing Guide

## Test Architecture

Fireshark uses three kinds of tests:

### Unit Tests (Inline)

Defined in `#[cfg(test)] mod tests` blocks inside source files. These test internal functions and logic at the module level.

Examples: color mapping, hex dump rendering, timestamp formatting, filter lexer/parser/evaluator.

### Integration Tests (Separate Files)

Defined in `crates/<crate>/tests/*.rs`. These test public APIs, cross-module behavior, and CLI commands from the outside.

Examples: dissector decode of full packets, capture file reading, CLI output verification, MCP session lifecycle.

### Fixture-Based Testing

All dissector and file reader tests use binary fixture files rather than constructing bytes inline. This keeps tests readable and makes it easy to inspect fixtures with external tools (Wireshark, hex editors).

- `fixtures/bytes/` -- handcrafted binary blobs representing single protocol headers or full packets
- `fixtures/smoke/` -- small pcap/pcapng capture files for integration and CLI tests

Fixtures are loaded with `include_bytes!("../../fixtures/bytes/<name>.bin")` in dissector tests, or by path in file reader and CLI tests.

## Running Tests

### Full Test Suite

```bash
just test
# or equivalently:
cargo test --workspace
```

### Single Crate

```bash
cargo test -p fireshark-core
cargo test -p fireshark-dissectors
cargo test -p fireshark-file
cargo test -p fireshark-filter
cargo test -p fireshark-cli
cargo test -p fireshark-mcp
cargo test -p fireshark-backend
cargo test -p fireshark-tshark
```

### Single Test by Name

```bash
cargo test -p fireshark-dissectors tcp_syn_ack
cargo test -p fireshark-filter parses_protocol_filter
```

### Full CI Gate

```bash
just check
# Runs: fmt-check, clippy (-D warnings), test
```

## Fixture Files

### `fixtures/bytes/` -- Protocol Binary Fixtures

Handcrafted binary blobs used by dissector unit/integration tests. Each file contains raw bytes representing one or more protocol headers as they would appear on the wire (no pcap framing).

| Fixture | Contents |
|---------|----------|
| `ethernet_arp.bin` | Ethernet + ARP request |
| `ethernet_ipv4_tcp.bin` | Ethernet + IPv4 + TCP |
| `ethernet_ipv4_udp.bin` | Ethernet + IPv4 + UDP |
| `ethernet_ipv6_icmp.bin` | Ethernet + IPv6 + ICMP |
| `arp_reply.bin` | ARP reply (no Ethernet header) |
| `arp_gratuitous.bin` | Gratuitous ARP |
| `ipv4_options.bin` | IPv4 with options (IHL > 5) |
| `ipv4_ttl_zero.bin` | IPv4 with TTL=0 |
| `ipv4_fragment_first.bin` | IPv4 first fragment (MF set) |
| `tcp_syn.bin` | TCP SYN segment |
| `tcp_syn_ack.bin` | TCP SYN-ACK segment |
| `tcp_rst.bin` | TCP RST segment |
| `tcp_data_offset_gt5.bin` | TCP with options (data offset > 5) |
| `icmp_echo_reply.bin` | ICMP echo reply |
| `icmp_dest_unreachable.bin` | ICMP destination unreachable |
| `udp_length_mismatch.bin` | UDP with length field mismatch |
| `ethernet_truncated.bin` | Truncated Ethernet frame |
| `ethernet_ipv4_udp_dns.bin` | Ethernet + IPv4 + UDP + DNS query |
| TLS fixtures | Ethernet + IPv4 + TCP + TLS ClientHello/ServerHello handshake messages |

### `fixtures/smoke/` -- Capture Files

Small pcap/pcapng files used by file reader, CLI, and MCP integration tests.

| Fixture | Format | Contents |
|---------|--------|----------|
| `minimal.pcap` | pcap | Minimal valid capture with one or more packets |
| `minimal.pcapng` | pcapng | Minimal valid pcapng capture |
| `fuzz-2006-06-26-2594.pcap` | pcap | Regression capture from fuzzing |

## Writing a New Test

### Dissector Test Pattern

1. Create a binary fixture file in `fixtures/bytes/` with the raw protocol bytes
2. Write a test that loads the fixture, decodes, and asserts on layer fields

```rust
// In crates/fireshark-dissectors/tests/<protocol>.rs

use fireshark_core::{Layer, Packet};
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_my_protocol() {
    let data = include_bytes!("../../../fixtures/bytes/my_protocol.bin");
    let packet = decode_packet(data);

    // Assert the expected layers are present
    let layers = packet.layers();
    assert_eq!(layers.len(), 3); // e.g., Ethernet + IPv4 + TCP

    // Assert specific field values
    match &layers[2] {
        Layer::Tcp(tcp) => {
            assert_eq!(tcp.source_port, 51514);
            assert_eq!(tcp.destination_port, 443);
            assert!(tcp.flags.syn);
        }
        other => panic!("expected TCP layer, got {other:?}"),
    }
}
```

### File Reader Test Pattern

```rust
// In crates/fireshark-file/tests/read_<format>.rs

use fireshark_file::CaptureReader;

#[test]
fn reads_my_capture() {
    let reader = CaptureReader::open("fixtures/smoke/my_capture.pcap").unwrap();
    let frames: Vec<_> = reader.collect::<Result<_, _>>().unwrap();

    assert_eq!(frames.len(), 5);
    assert_eq!(frames[0].captured_len(), 54);
}
```

### CLI Test Pattern

```rust
// In crates/fireshark-cli/tests/<command>.rs

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn summary_shows_packet_count() {
    Command::cargo_bin("fireshark")
        .unwrap()
        .args(["summary", "fixtures/smoke/minimal.pcap"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TCP"));
}
```

### Error Case Test Pattern

```rust
#[test]
fn rejects_truncated_header() {
    let data = &[0u8; 4]; // too short for any protocol
    let packet = decode_packet(data);

    // Should have a decode issue
    assert!(!packet.issues().is_empty());
}
```

## Fuzz Testing

### Setup

Fuzz testing requires the nightly Rust toolchain and `cargo-fuzz`:

```bash
rustup install nightly
cargo +nightly install cargo-fuzz
```

### Running Fuzz Targets

```bash
cd fuzz

# Fuzz the dissector chain (raw bytes as Ethernet frames)
cargo +nightly fuzz run fuzz_decode_packet -- -max_total_time=60

# Fuzz the capture file reader (raw bytes as pcap/pcapng files)
cargo +nightly fuzz run fuzz_capture_reader -- -max_total_time=60
```

### What the Fuzz Targets Do

**`fuzz_decode_packet`** -- feeds arbitrary bytes into `fireshark_dissectors::decode_packet()`. The assertion is that it never panics. Errors (truncated, malformed) are expected and fine.

**`fuzz_capture_reader`** -- writes arbitrary bytes to a temp file and opens it with `CaptureReader::open()`. The assertion is that invalid input produces errors, not panics.

### Interpreting Results

- **No crashes after N seconds**: good. The code handles arbitrary input gracefully.
- **Crash found**: an artifact file is saved to `fuzz/artifacts/<target>/`. Reproduce with:
  ```bash
  cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<artifact-file>
  ```
- **Regression testing**: copy crash artifacts to `fixtures/bytes/` or `fixtures/smoke/` and add a test.

## Test Coverage by Crate

### fireshark-core (46 tests)

- Packet model construction and layer access
- Frame summary generation (protocol, source, destination, length)
- Pipeline iteration over frame sources
- TrackingPipeline: stream ID assignment, metadata accumulation
- StreamTracker: key normalization, direction symmetry, IPv4/IPv6, protocol separation
- StreamKey: canonical 5-tuple ordering, protocol name
- Summary rendering

### fireshark-dissectors (68 tests)

- Full decode of Ethernet + ARP, IPv4, IPv6 packets
- Transport protocol decoding: TCP (SYN, SYN-ACK, RST, options), UDP, ICMP (echo, dest unreachable)
- Application-layer decoding: DNS (query, response, A/AAAA answers, truncated, malformed), TLS (ClientHello, ServerHello, SNI extraction, cipher suites, heuristic dispatch)
- Edge cases: truncated headers, malformed fields, zero-length payloads, TTL=0, fragments
- IPv4 options handling, data offset validation

### fireshark-file (10 tests)

- pcap file reading with correct frame data and metadata
- pcapng file reading
- Rejection of unsupported link types (non-Ethernet)
- Rejection of short/invalid capture files

### fireshark-filter (110 tests)

- Lexer tokenization for all token types
- Parser: protocol presence, field comparisons, boolean operators, shorthands, CIDR, parentheses, precedence
- Evaluator: field resolution against decoded packets, all comparison operators, boolean logic
- DNS filter fields: dns.id, dns.qr, dns.opcode, dns.qcount, dns.acount, dns.qtype
- TLS filter fields: tls.handshake.type, tls.record_version, tls.client_version, tls.selected_version, tls.cipher_suite
- Stream filter fields: tcp.stream, udp.stream (presence check and integer comparison)
- Error cases: invalid syntax, unknown fields

### fireshark-cli (55 tests)

- Summary command output format and content
- Detail command: layer tree rendering, hex dump, packet-not-found errors
- Follow command: stream output, error on invalid stream ID
- Stats command: packet count, stream count, protocol distribution
- Issues command: decode issue listing
- Audit command: security heuristic output
- Backend selection: `--backend native|tshark` flag
- Display filter integration: filter flag parsing and application
- Color mapping: protocol-to-color assignments, case insensitivity, DNS=Magenta
- Hex dump: row formatting, multi-row, legend, span coloring
- Timestamp formatting: epoch, milliseconds, leap years
- Fuzz regression tests
- Runtime path and Justfile documentation consistency checks

### fireshark-mcp (33 tests)

- Session lifecycle: open, describe, close
- Packet queries: list, get, search
- Stream queries: list_streams, get_stream
- Capture overview: summarize_capture
- Audit: capture audit, findings, explain
- Server help output and stdio smoke test
- Session manager: creation, limits

### fireshark-backend (19 tests)

- BackendCapture: open with native and tshark backends
- BackendKind: parsing from strings, default selection
- BackendCapabilities: feature queries per backend
- BackendPacket: summary, layers, issues normalization
- Differential tests: native vs tshark output comparison for stable packet facts

### fireshark-tshark (10 tests)

- TsharkVersion: parsing, comparison, validation
- Discovery: PATH search, known locations, version check
- Execution: TSV output parsing, field extraction
- Error handling: missing tshark, version too old, invalid output

## Current Metrics

| Metric | Value |
|--------|-------|
| Total tests | 351 |
| Byte fixtures | 18 |
| Smoke captures | 3 |
| Total fixtures | 21 |
| Crates tested | 8 |
| Fuzz targets | 2 |
| Test failures | 0 |

### Known Gaps

- No HTTP application-layer protocol tests -- HTTP is not yet implemented
- No IP fragment reassembly tests -- reassembly is not yet implemented
- No TCP stream reassembly tests -- stream tracking (conversation identity) is implemented, but byte-level reassembly is not
- No performance/benchmark tests
- No property-based tests (outside of fuzzing)
- MCP tests do not cover the 15-minute idle timeout or the 100k packet limit at scale

---

**Version:** 0.5.2 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
