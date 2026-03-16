# Dissector Hardening Pass — Design Spec

## Purpose

Harden the existing protocol dissectors by extracting commonly-needed RFC fields, adding edge case tests with new fixtures, integrating the orphaned fuzz fixture, and setting up `cargo-fuzz` infrastructure. This completes the crawl phase's "decode" requirement with analysis-grade field coverage.

## Field Extraction Changes

Each protocol layer struct in `fireshark-core::layer` gains new fields. The `Layer` enum variants stay the same — we expand the structs they wrap. All new fields are parsed from bytes already being read by the existing dissectors.

New public types (`TcpFlags`, `IcmpDetail`) must be added to the `pub use` exports in `fireshark-core/src/lib.rs`.

### Ipv4Layer

New fields:
- `ttl: u8` — byte 8
- `identification: u16` — bytes 4-5
- `dscp: u8` — top 6 bits of the TOS byte (byte 1), `bytes[1] >> 2`
- `ecn: u8` — bottom 2 bits of the TOS byte (byte 1), `bytes[1] & 0x03`
- `dont_fragment: bool` — bit 1 of the flags nibble at byte offset 6, mask `0x4000` on the `u16::from_be_bytes([bytes[6], bytes[7]])` word (same word that already extracts `more_fragments` via `0x2000` and `fragment_offset` via `0x1FFF`)
- `header_checksum: u16` — bytes 10-11, raw value, no validation (see GitHub issue #8)

### Ipv6Layer

New fields:
- `traffic_class: u8` — 8 bits from the version/TC/flow-label word at bytes 0-3. Extract as `((bytes[0] & 0x0F) << 4) | (bytes[1] >> 4)`
- `flow_label: u32` — 20 bits from bytes 1-3. Extract as `u32::from_be_bytes([0, bytes[1] & 0x0F, bytes[2], bytes[3]])`
- `hop_limit: u8` — byte 7

Note: The existing dissector already reads `payload_len` from bytes 4-5 but does not store it in the layer struct. Adding `payload_length: u16` to `Ipv6Layer` is deferred — it is used internally for truncation detection but not needed for analysis in this pass.

### TcpLayer

New fields:
- `seq: u32` — bytes 4-7
- `ack: u32` — bytes 8-11
- `flags: TcpFlags` — parsed from `u16::from_be_bytes([bytes[12], bytes[13]]) & 0x01FF`. Bit layout: CWR(7), ECE(6), URG(5), ACK(4), PSH(3), RST(2), SYN(1), FIN(0). The NS (Nonce Sum, bit 8, RFC 3540 experimental) flag is omitted — it is rarely used in practice and can be added later if needed.
- `window: u16` — bytes 14-15
- `data_offset: u8` — upper 4 bits of byte 12, `bytes[12] >> 4`

`TcpFlags` is a plain struct with public `bool` fields: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`. Defined alongside `TcpLayer` in `fireshark-core::layer`. Derives `Debug, Clone, Copy, PartialEq, Eq`.

The TCP dissector must validate:
- `data_offset >= 5` — values below 5 produce `DecodeError::Malformed`
- `data_offset * 4 <= bytes.len()` — if the data offset claims options exist but the buffer is too short, return `DecodeError::Truncated`

Values of `data_offset > 5` indicate TCP options are present — the dissector skips over the options bytes (no parsing) and adjusts the payload offset accordingly.

### UdpLayer

New field:
- `length: u16` — bytes 4-5, raw header value. No validation against captured data length (callers can compare `length` to `data.len()` if needed).

### IcmpLayer

Existing fields stay: `type_: u8`, `code: u8`.

New field:
- `detail: Option<IcmpDetail>` — a typed enum wrapped in `Option`:

```
IcmpDetail::EchoRequest { identifier: u16, sequence: u16 }
IcmpDetail::EchoReply { identifier: u16, sequence: u16 }
IcmpDetail::DestinationUnreachable { next_hop_mtu: u16 }
IcmpDetail::Other { rest_of_header: u32 }
```

`EchoRequest` matches type 8, `EchoReply` matches type 0. `DestinationUnreachable` matches type 3 (next_hop_mtu from bytes 6-7, only meaningful for code 4 but always parsed for type 3). Everything else falls to `Other` with the raw 4-byte rest-of-header field (bytes 4-7).

The ICMP dissector needs 8 bytes for typed detail parsing (4 byte header + 4 byte rest-of-header). If only 4 bytes are available (the current minimum), parse type/code and set `detail: None` — the data is absent, not zero. If 8+ bytes are available, parse the typed detail.

`IcmpDetail` derives `Debug, Clone, Copy, PartialEq, Eq`.

### Ethernet

No new fields. Already complete for the standard 14-byte header.

### ARP

No new fields in this pass. The current `ArpLayer` extracts `operation`, `sender_protocol_addr`, and `target_protocol_addr`. Hardware addresses (`sender_hardware_addr`, `target_hardware_addr`) are present in the RFC but deferred — they are parsed and discarded by the current dissector. Adding them is a small follow-up.

## New Edge Case Tests & Fixtures

### New binary fixtures in `fixtures/bytes/`

| Fixture | Purpose |
|---------|---------|
| `arp_reply.bin` | ARP reply (operation=2) |
| `arp_gratuitous.bin` | Gratuitous ARP (sender IP == target IP) |
| `ipv4_options.bin` | IPv4 with IHL > 5 — options present, verify skip without crash |
| `ipv4_ttl_zero.bin` | TTL=0 — valid parse, verify ttl field |
| `ipv4_fragment_first.bin` | First fragment (offset=0, MF=1) with transport header |
| `tcp_syn.bin` | SYN-only flag set |
| `tcp_syn_ack.bin` | SYN+ACK flags |
| `tcp_rst.bin` | RST flag |
| `tcp_data_offset_gt5.bin` | TCP with options (data_offset > 5) |
| `udp_length_mismatch.bin` | UDP length field != captured data length |
| `icmp_echo_reply.bin` | ICMP type 0 with identifier and sequence |
| `icmp_dest_unreachable.bin` | ICMP type 3 with next_hop_mtu |
| `ethernet_truncated.bin` | < 14 bytes |

All fixtures are handcrafted binary blobs following the established pattern: minimal valid headers with known field values for assertion.

### New tests without fixtures

These use inline byte slices or modify existing fixtures:

- ARP with truncated payload (< 28 bytes after Ethernet) → `DecodeError::Truncated`
- ARP with non-Ethernet hardware type → `DecodeError::Malformed`
- IPv6 with hop_limit=0 — valid parse, verify field
- TCP with data_offset < 5 → `DecodeError::Malformed`
- TCP with data_offset * 4 > buffer length → `DecodeError::Truncated`
- ICMP with exactly 4 bytes — type/code parsed, detail is `None`
- Ethernet with unknown EtherType — parse succeeds, no next-layer decode

### Fuzz fixture integration

The orphaned `fixtures/smoke/fuzz-2006-06-26-2594.pcap` (108KB) gets a regression test in `crates/fireshark-cli/tests/` (which already depends on both `fireshark-file` and `fireshark-dissectors`):

```rust
#[test]
fn fuzz_fixture_does_not_panic() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    for decoded in Pipeline::new(reader, decode_packet) {
        let _ = decoded; // Don't care about errors, just no panics
    }
}
```

The `support::repo_root()` helper already exists in `crates/fireshark-cli/tests/support/mod.rs`.

No assertions on content. The test documents that the pipeline handles adversarial input gracefully.

## Fuzz Testing Infrastructure

### Setup

Create a top-level `fuzz/` directory using `cargo-fuzz` with `libFuzzer`.

### Fuzz targets

| Target | Input | Exercises |
|--------|-------|-----------|
| `fuzz_decode_packet` | Raw bytes treated as a complete Ethernet frame | Full Ethernet→transport dissector chain via `decode_packet()` |
| `fuzz_capture_reader` | Raw bytes written to a temp file | pcap/pcapng header parsing + frame iteration via `CaptureReader::open()` |

### Harness pattern

```rust
// fuzz/fuzz_targets/fuzz_decode_packet.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fireshark_dissectors::decode_packet(data);
});
```

```rust
// fuzz/fuzz_targets/fuzz_capture_reader.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(data).unwrap();
    let path = tmp.path().to_path_buf();
    if let Ok(reader) = fireshark_file::CaptureReader::open(&path) {
        for frame in reader {
            let _ = frame;
        }
    }
});
```

The capture reader fuzz target uses `tempfile::NamedTempFile` to write fuzzer input to disk, since `CaptureReader` only accepts a path. This adds I/O overhead per iteration but is correct and avoids changing the `fireshark-file` public API. The `tempfile` crate is added as a dev-dependency of the fuzz crate only.

### Out of scope

- CI integration for continuous fuzzing
- Coverage-guided corpus management
- OSS-Fuzz submission
- Corpus seeding beyond the existing fixtures

## MCP View Updates

### LayerView changes

`LayerView::Ipv4` gains: `ttl: u8`, `identification: u16`, `dscp: u8`, `ecn: u8`, `dont_fragment: bool`, `header_checksum: u16`

`LayerView::Ipv6` gains: `traffic_class: u8`, `flow_label: u32`, `hop_limit: u8`

`LayerView::Tcp` gains: `seq: u32`, `ack: u32`, `flags: TcpFlagsView` (object with bool fields matching `TcpFlags`), `window: u16`, `data_offset: u8`

`LayerView::Udp` gains: `length: u16`

`LayerView::Icmp` — keep `type_: u8`, `code: u8`. Add `detail` field: serialized as the typed variant object (e.g., `{"type": "EchoRequest", "identifier": 1, "sequence": 1}`) when `Some`, or `null` when `None` (4-byte ICMP with no rest-of-header). For `IcmpDetail::Other`, serialize as `{"type": "Other", "rest_of_header": 12345}` — the raw data is preserved, not discarded.

### MCP test additions

One new test: open minimal fixture, get packet detail, verify TCP layer view contains expected flag values and seq/ack fields.

## Testing Strategy

Tests follow the existing pattern: `include_bytes!` fixtures in integration test files under `crates/fireshark-dissectors/tests/`. Tests assert on specific field values from known fixtures.

The fuzz regression test goes in `crates/fireshark-cli/tests/` since it already depends on both `fireshark-file` and `fireshark-dissectors`.

All existing tests must be updated to construct layer structs with the new fields.

## Out of Scope

- Checksum validation (GitHub issue #8)
- IP options parsing, TCP options parsing, IPv6 extension headers (GitHub issue #9)
- VLAN tagging (802.1Q, QinQ)
- Application-layer protocol detection
- New dissectors (DNS, HTTP, TLS)
- ARP hardware address fields (small follow-up)
- IPv6 `payload_length` in layer struct (used internally, not stored)
