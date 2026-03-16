# CLI Detail Command — Design Spec

## Purpose

Add a `detail` subcommand to the CLI that shows decoded layer fields and a color-coded hex dump for a single packet. This is the second of three CLI UX specs (color, detail+hex, filters).

## CLI Interface

```
fireshark detail <file> <packet-number>
```

- `packet-number` is 1-indexed, matching the summary output
- Out-of-range packet numbers print an error to stderr and exit non-zero
- The command reads the capture, advances the pipeline iterator to the Nth packet, and renders the detail view

## Layer Span Tracking

### New type: `LayerSpan`

Add to `fireshark-core::packet`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerSpan {
    pub offset: usize,
    pub len: usize,
}
```

Represents the byte range `[offset..offset+len)` within the raw frame data that a decoded layer occupies. Derives `Debug, Clone, Copy, PartialEq, Eq` to match the traits on `Packet`.

### Changes to `Packet`

Add a parallel `Vec<LayerSpan>` stored alongside the existing `Vec<Layer>`. New accessor: `pub fn spans(&self) -> &[LayerSpan]`. The spans vec is indexed identically to the layers vec — `spans()[i]` describes the byte range of `layers()[i]`.

To avoid breaking existing call sites, add a new constructor:

```rust
pub fn with_spans(layers: Vec<Layer>, issues: Vec<DecodeIssue>, spans: Vec<LayerSpan>) -> Self
```

Refactor `Packet::new(layers, issues)` to call `Self::with_spans(layers, issues, Vec::new())` internally, keeping a single field initialization path.

### Dissector changes

Update `decode_packet()` in `fireshark-dissectors/src/lib.rs` to build a `Vec<LayerSpan>` alongside `Vec<Layer>`. The spans are computed from values already available in `decode_packet`:

- **Ethernet:** offset 0, len 14 (fixed)
- **ARP:** offset 14, len 28 (fixed `HEADER_LEN` in `arp.rs`)
- **IPv4:** offset 14, len = `payload_offset - 14`. The IPv4 parser sets `payload_offset = 14 + header_len` where `header_len = IHL * 4`. Since `IHL` is not stored in `Ipv4Layer`, derive the span length from `payload_offset` which is already returned in `NetworkPayload`.
- **IPv6:** offset 14, len 40 (fixed `HEADER_LEN`)
- **TCP:** offset = `payload_offset`, len = `data_offset * 4`. The `data_offset` field is stored in `TcpLayer` and available after parsing. However, at the point where the span is recorded in `decode_packet`, the transport layer has just been decoded — extract `data_offset` from the returned `Layer::Tcp` variant.
- **UDP:** offset = `payload_offset`, len 8 (fixed `HEADER_LEN`)
- **ICMP:** offset = `payload_offset`, len = 8 if `detail.is_some()`, 4 if `detail.is_none()`. Extract from the returned `Layer::Icmp` variant.

Pass spans to `Packet::with_spans()` instead of `Packet::new()`.

When a layer fails to decode (producing a `DecodeIssue` instead of a `Layer`), no span is added — the spans vec only contains entries for successfully decoded layers.

## Layer Tree Rendering

The detail command prints a header, then each layer with indented fields:

```
Packet 1 · 54 bytes · 2005-07-04T09:32:20.839Z
─────────────────────────────────────────────────
▸ Ethernet
    Destination: 00:11:22:33:44:55
    Source:      66:77:88:99:aa:bb
    EtherType:   0x0800 (IPv4)
▸ IPv4
    Source:      192.168.1.2
    Destination: 198.51.100.20
    TTL: 64  Protocol: 6 (TCP)  ID: 0x0001  [DF]
    DSCP: 0  ECN: 0  Checksum: 0x0000
▸ TCP
    51514 → 443  Seq: 1  Ack: 0  [SYN]  Win: 1024
    Data Offset: 5 (20 bytes)
```

**Header line:** `Packet {n} · {len} bytes · {timestamp}` where `len` is `frame.captured_len()` and timestamp is from `frame.timestamp()` formatted with the existing `timestamp::format_utc()`. If no timestamp, show `-`.

**Raw frame bytes** for the hex dump come from `frame.data()` on the `DecodedFrame`.

Layer name lines (`▸ Ethernet`) are colored using the Wireshark protocol colors from `color.rs`. Field lines use default/dim color.

Decode issues are printed after the last layer:

```
⚠ Truncated at offset 39
```

### Field formatting per layer

**Ethernet:** Destination, Source (colon-separated hex), EtherType (hex + name if known: IPv4, IPv6, ARP).

**ARP:** Operation (1=request, 2=reply, else numeric), Sender IP, Target IP.

**IPv4:** Source, Destination, TTL, Protocol (number + name if known), ID (hex), flags — show `[DF]` if `dont_fragment`, `[MF]` if `more_fragments`, omit each if false. DSCP, ECN, Checksum (hex).

**IPv6:** Source, Destination, Next Header (number + name if known), Traffic Class, Flow Label, Hop Limit.

**TCP:** Source → Destination ports, Seq, Ack, flags — show each set flag as `[SYN]` `[ACK]` `[FIN]` `[RST]` `[PSH]` `[URG]` `[ECE]` `[CWR]`, omit unset. Window, Data Offset (value + byte count).

**UDP:** Source → Destination ports, Length.

**ICMP:** Type (number + name if known), Code. For echo request/reply: Identifier, Sequence. For destination unreachable: Next Hop MTU.

The rendering logic lives in `crates/fireshark-cli/src/detail.rs` as a `render_layer_tree()` function that matches on `Layer` variants.

## Color-Coded Hex Dump

Below the layer tree, render the raw frame bytes in 16-bytes-per-line hex+ASCII format:

```
─── Hex Dump ──────────────────────────────────
0000  00 11 22 33 44 55 66 77  88 99 aa bb 08 00 45 00  .."3DUfw......E.
0010  00 28 00 01 40 00 40 06  00 00 c0 a8 01 02 c6 33  .(...@.@.......3
0020  64 14 c9 3a 01 bb 00 00  00 01 00 00 00 00 50 02  d..:..........P.
0030  04 00 00 00 00 00                                  ......
  ■ Ethernet  ■ IPv4  ■ TCP
```

Each byte's hex value is colored based on which `LayerSpan` it falls within, using the same protocol color map as the summary view. Bytes outside any span are printed in default/dim color. The ASCII column is always dim/uncolored.

A legend line at the bottom shows the color-to-layer mapping using filled squares.

### Format details

- **Offset column:** 4-digit lowercase hex (`0000`, `0010`, ...). Sufficient for packets up to 65535 bytes.
- **Hex columns:** Two groups of 8 bytes separated by an extra space (matching `xxd` layout).
- **ASCII column:** Printable bytes (0x20-0x7E) shown as-is, non-printable as `.`.

The hex dump logic lives in `crates/fireshark-cli/src/hexdump.rs`. It takes `data: &[u8]` and `spans: &[(LayerSpan, &str)]` (span + protocol name for color lookup) and writes formatted output to a `Write` sink.

### Building the spans argument for hexdump

The caller in `detail.rs` zips `packet.layers()` with `packet.spans()` to build the `&[(LayerSpan, &str)]` input:

```rust
let span_colors: Vec<(LayerSpan, &str)> = packet
    .layers()
    .iter()
    .zip(packet.spans())
    .map(|(layer, span)| (*span, layer.name()))
    .collect();
```

### Ethernet color

Add `"ETHERNET"` to the color map in `color.rs`, mapping to white (same as IPv4/IPv6). This prevents Ethernet bytes from falling through to the red/unknown color in the hex dump.

## New Files

| File | Purpose |
|------|---------|
| `crates/fireshark-cli/src/detail.rs` | Detail subcommand handler + layer tree renderer |
| `crates/fireshark-cli/src/hexdump.rs` | Hex dump formatter with layer-span coloring |

## Modified Files

| File | Change |
|------|--------|
| `crates/fireshark-core/src/packet.rs` | Add `LayerSpan`, `with_spans()`, `spans()` |
| `crates/fireshark-core/src/lib.rs` | Export `LayerSpan` |
| `crates/fireshark-dissectors/src/lib.rs` | Populate spans in `decode_packet()` |
| `crates/fireshark-cli/src/main.rs` | Add `detail` subcommand to clap, register new modules |
| `crates/fireshark-cli/src/color.rs` | Add `"ETHERNET"` to the color map |

## Dependencies

No new dependencies. The `colored` crate is already in `fireshark-cli`. A lower-level color helper (returning a `Color` value for a protocol name, not a full `ColoredString`) will be added to `color.rs` so that both `colorize()` and the hex dump formatter can share the protocol-to-color mapping.

## Testing

- **`fireshark-core` unit tests:** `Packet::with_spans()` stores spans, `Packet::new()` produces empty spans, `spans()` accessor works.
- **`hexdump.rs` unit tests:** Format a known byte slice with known spans, assert exact output (with color override forced). Test empty input, bytes outside spans, single-byte span.
- **`detail.rs` unit tests:** Decode a fixture packet via `decode_packet`, render layer tree to a `String`, assert output contains expected field strings.
- **CLI integration tests:** `fireshark detail fixtures/smoke/minimal.pcap 1` succeeds with expected content. `fireshark detail fixtures/smoke/minimal.pcap 999` fails with error message.

## Out of Scope

- Interactive/scrollable packet view
- Display filter language (Spec 3)
- Payload/application data decoding
- Configurable field display (always show all fields)
