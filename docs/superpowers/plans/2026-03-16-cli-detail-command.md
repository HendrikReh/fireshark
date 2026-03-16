# CLI Detail Command Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `fireshark detail <file> <packet-number>` command that shows decoded layer fields and a color-coded hex dump for a single packet.

**Architecture:** Add `LayerSpan` to `fireshark-core::packet` for byte-range tracking. Update `decode_packet` to populate spans. Add two new CLI modules: `detail.rs` (layer tree renderer + subcommand handler) and `hexdump.rs` (color-coded hex dump formatter). Add a lower-level `protocol_color()` helper to `color.rs`.

**Tech Stack:** Rust, `colored` crate (already a CLI dependency).

**Spec:** `docs/superpowers/specs/2026-03-16-cli-detail-command-design.md`

---

## Chunk 1: Core changes (LayerSpan + Packet)

### Task 1: Add LayerSpan and update Packet

**Files:**
- Modify: `crates/fireshark-core/src/packet.rs`
- Modify: `crates/fireshark-core/src/lib.rs`
- Modify: `crates/fireshark-core/tests/packet_model.rs`

- [ ] **Step 1: Write failing test for LayerSpan and with_spans**

In `crates/fireshark-core/tests/packet_model.rs`, add:

```rust
use fireshark_core::LayerSpan;

#[test]
fn packet_with_spans_stores_and_returns_spans() {
    let packet = Packet::with_spans(
        vec![Layer::Unknown],
        vec![],
        vec![LayerSpan { offset: 0, len: 14 }],
    );

    assert_eq!(packet.spans().len(), 1);
    assert_eq!(packet.spans()[0].offset, 0);
    assert_eq!(packet.spans()[0].len, 14);
}

#[test]
fn packet_new_has_empty_spans() {
    let packet = Packet::new(vec![Layer::Unknown], vec![]);
    assert!(packet.spans().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p fireshark-core packet_with_spans -- --exact`
Expected: FAIL — `LayerSpan` and `with_spans` don't exist

- [ ] **Step 3: Add LayerSpan and update Packet**

In `crates/fireshark-core/src/packet.rs`:

```rust
use crate::{DecodeIssue, Layer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerSpan {
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    layers: Vec<Layer>,
    issues: Vec<DecodeIssue>,
    spans: Vec<LayerSpan>,
}

impl Packet {
    pub fn new(layers: Vec<Layer>, issues: Vec<DecodeIssue>) -> Self {
        Self::with_spans(layers, issues, Vec::new())
    }

    pub fn with_spans(
        layers: Vec<Layer>,
        issues: Vec<DecodeIssue>,
        spans: Vec<LayerSpan>,
    ) -> Self {
        Self {
            layers,
            issues,
            spans,
        }
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    pub fn issues(&self) -> &[DecodeIssue] {
        &self.issues
    }

    pub fn spans(&self) -> &[LayerSpan] {
        &self.spans
    }

    pub fn layer_names(&self) -> Vec<&'static str> {
        self.layers.iter().map(Layer::name).collect()
    }

    pub fn transport_ports(&self) -> Option<(u16, u16)> {
        self.layers.iter().find_map(|layer| match layer {
            Layer::Tcp(layer) => Some((layer.source_port, layer.destination_port)),
            Layer::Udp(layer) => Some((layer.source_port, layer.destination_port)),
            _ => None,
        })
    }
}
```

- [ ] **Step 4: Export LayerSpan in lib.rs**

In `crates/fireshark-core/src/lib.rs`, update:

```rust
pub use packet::{LayerSpan, Packet};
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p fireshark-core`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/fireshark-core/src/packet.rs crates/fireshark-core/src/lib.rs \
       crates/fireshark-core/tests/packet_model.rs
git commit -m "feat: add LayerSpan and Packet::with_spans for byte-range tracking"
```

### Task 2: Populate spans in decode_packet

**Files:**
- Modify: `crates/fireshark-dissectors/src/lib.rs`

- [ ] **Step 1: Update decode_packet to build spans**

Replace `crates/fireshark-dissectors/src/lib.rs`:

```rust
mod arp;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

pub use error::DecodeError;

use fireshark_core::{DecodeIssue, Layer, LayerSpan, Packet};

pub(crate) struct NetworkPayload<'a> {
    pub(crate) layer: Layer,
    pub(crate) protocol: u8,
    pub(crate) payload: &'a [u8],
    pub(crate) payload_offset: usize,
    pub(crate) issues: Vec<DecodeIssue>,
}

pub fn decode_packet(bytes: &[u8]) -> Result<Packet, DecodeError> {
    let (ethernet, payload) = ethernet::parse(bytes)?;
    let ether_type = ethernet.ether_type;
    let mut layers = vec![Layer::Ethernet(ethernet)];
    let mut spans = vec![LayerSpan { offset: 0, len: 14 }];
    let mut issues = Vec::new();

    match ether_type {
        arp::ETHER_TYPE => {
            append_layer_with_span(
                arp::parse(payload),
                14,
                LayerSpan { offset: 14, len: 28 },
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        ipv4::ETHER_TYPE => {
            append_network_layer(
                ipv4::parse(payload),
                14,
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        ipv6::ETHER_TYPE => {
            append_network_layer(
                ipv6::parse(payload),
                14,
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        _ => {}
    }

    Ok(Packet::with_spans(layers, issues, spans))
}

fn append_layer_with_span(
    layer: Result<Layer, DecodeError>,
    layer_offset: usize,
    span: LayerSpan,
    layers: &mut Vec<Layer>,
    spans: &mut Vec<LayerSpan>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok(layer) => {
            layers.push(layer);
            spans.push(span);
        }
        Err(DecodeError::Truncated { offset, .. }) => issues.push(DecodeIssue::truncated(offset)),
        Err(DecodeError::Malformed(_)) => issues.push(DecodeIssue::malformed(layer_offset)),
    }
}

fn transport_span(layer: &Layer, payload_offset: usize) -> LayerSpan {
    let len = match layer {
        Layer::Tcp(tcp) => usize::from(tcp.data_offset) * 4,
        Layer::Udp(_) => 8,
        Layer::Icmp(icmp) => {
            if icmp.detail.is_some() {
                8
            } else {
                4
            }
        }
        _ => 0,
    };
    LayerSpan {
        offset: payload_offset,
        len,
    }
}

fn append_network_layer(
    layer: Result<NetworkPayload<'_>, DecodeError>,
    layer_offset: usize,
    layers: &mut Vec<Layer>,
    spans: &mut Vec<LayerSpan>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok(NetworkPayload {
            layer,
            protocol,
            payload,
            payload_offset,
            issues: network_issues,
        }) => {
            let network_span = LayerSpan {
                offset: layer_offset,
                len: payload_offset - layer_offset,
            };
            let transport_header_available = match &layer {
                Layer::Ipv4(layer) => layer.fragment_offset == 0,
                _ => true,
            };
            layers.push(layer);
            spans.push(network_span);
            issues.extend(network_issues);
            if payload.is_empty() || !transport_header_available {
                return;
            }
            let parse_transport = |result: Result<Layer, DecodeError>,
                                    layers: &mut Vec<Layer>,
                                    spans: &mut Vec<LayerSpan>,
                                    issues: &mut Vec<DecodeIssue>| {
                let span = match &result {
                    Ok(layer) => transport_span(layer, payload_offset),
                    Err(_) => LayerSpan {
                        offset: payload_offset,
                        len: 0,
                    },
                };
                append_layer_with_span(result, payload_offset, span, layers, spans, issues);
            };
            match protocol {
                tcp::IP_PROTOCOL => {
                    parse_transport(
                        tcp::parse(payload, payload_offset),
                        layers,
                        spans,
                        issues,
                    );
                }
                udp::IP_PROTOCOL => {
                    parse_transport(
                        udp::parse(payload, payload_offset),
                        layers,
                        spans,
                        issues,
                    );
                }
                icmp::IPV4_PROTOCOL | icmp::IPV6_PROTOCOL => {
                    parse_transport(
                        icmp::parse(payload, payload_offset),
                        layers,
                        spans,
                        issues,
                    );
                }
                _ => {}
            }
        }
        Err(error) => {
            append_layer_with_span(
                Err(error),
                layer_offset,
                LayerSpan {
                    offset: layer_offset,
                    len: 0,
                },
                layers,
                spans,
                issues,
            );
        }
    }
}
```

- [ ] **Step 2: Run all dissector tests**

Run: `cargo test -p fireshark-dissectors`
Expected: PASS — all existing tests still work (spans are additive)

- [ ] **Step 3: Add a span verification test**

Add to `crates/fireshark-dissectors/tests/transport.rs`:

```rust
use fireshark_core::LayerSpan;

#[test]
fn decode_packet_produces_layer_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    let spans = packet.spans();
    assert_eq!(spans.len(), 3, "Ethernet + IPv4 + TCP");

    // Ethernet: offset 0, len 14
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 });
    // IPv4: offset 14, len 20 (IHL=5, no options)
    assert_eq!(spans[1], LayerSpan { offset: 14, len: 20 });
    // TCP: offset 34, len 20 (data_offset=5)
    assert_eq!(spans[2], LayerSpan { offset: 34, len: 20 });
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p fireshark-dissectors decode_packet_produces_layer_spans`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-dissectors/src/lib.rs crates/fireshark-dissectors/tests/transport.rs
git commit -m "feat: populate layer spans in decode_packet"
```

---

## Chunk 2: CLI modules (color helper, hexdump, detail, subcommand)

### Task 3: Add protocol_color helper to color.rs

**Files:**
- Modify: `crates/fireshark-cli/src/color.rs`

- [ ] **Step 1: Add protocol_color function and Ethernet mapping**

Add to `crates/fireshark-cli/src/color.rs`, before the existing `colorize` function:

```rust
use colored::Color;

/// Return the ANSI color for a protocol name.
pub fn protocol_color(protocol: &str) -> Color {
    match protocol.to_ascii_uppercase().as_str() {
        "TCP" => Color::Green,
        "UDP" => Color::Blue,
        "ARP" => Color::Yellow,
        "ICMP" => Color::Cyan,
        "ETHERNET" | "IPV4" | "IPV6" => Color::White,
        _ => Color::Red,
    }
}
```

Refactor `colorize` to use `protocol_color`:

```rust
pub fn colorize(protocol: &str, line: &str) -> ColoredString {
    line.color(protocol_color(protocol))
}
```

- [ ] **Step 2: Add test for Ethernet color and protocol_color**

Add to the test module:

```rust
    #[test]
    fn ethernet_is_white() {
        let cs = colorize("Ethernet", "test");
        assert_eq!(cs.fgcolor, Some(Color::White));
    }

    #[test]
    fn protocol_color_returns_correct_colors() {
        assert_eq!(protocol_color("TCP"), Color::Green);
        assert_eq!(protocol_color("UDP"), Color::Blue);
        assert_eq!(protocol_color("Ethernet"), Color::White);
        assert_eq!(protocol_color("Unknown"), Color::Red);
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p fireshark-cli color`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/fireshark-cli/src/color.rs
git commit -m "feat: add protocol_color helper and Ethernet color mapping"
```

### Task 4: Create hexdump module

**Files:**
- Create: `crates/fireshark-cli/src/hexdump.rs`
- Modify: `crates/fireshark-cli/src/main.rs`

- [ ] **Step 1: Create hexdump.rs with render function and tests**

Create `crates/fireshark-cli/src/hexdump.rs`:

```rust
use std::fmt::Write as _;
use std::io::Write;

use colored::Colorize;
use fireshark_core::LayerSpan;

use crate::color;

/// Render a color-coded hex dump of raw packet bytes.
///
/// Each byte is colored based on which layer span it falls within.
/// Format: 16 bytes per line, two groups of 8, with ASCII column.
pub fn render<W: Write>(
    writer: &mut W,
    data: &[u8],
    spans: &[(LayerSpan, &str)],
) -> std::io::Result<()> {
    writeln!(writer, "─── Hex Dump ──────────────────────────────────")?;

    for line_start in (0..data.len()).step_by(16) {
        let line_end = (line_start + 16).min(data.len());
        let line_bytes = &data[line_start..line_end];

        // Offset column
        write!(writer, "{:04x}  ", line_start)?;

        // Hex columns
        let mut hex_part = String::new();
        for (i, &byte) in line_bytes.iter().enumerate() {
            let offset = line_start + i;
            let hex = format!("{byte:02x}");
            let colored_hex = match find_span(offset, spans) {
                Some(protocol) => format!("{}", hex.color(color::protocol_color(protocol))),
                None => format!("{}", hex.dimmed()),
            };
            hex_part.push_str(&colored_hex);
            hex_part.push(' ');
            if i == 7 {
                hex_part.push(' ');
            }
        }
        // Pad if fewer than 16 bytes
        let missing = 16 - line_bytes.len();
        for i in 0..missing {
            hex_part.push_str("   ");
            if line_bytes.len() + i == 7 {
                hex_part.push(' ');
            }
        }

        // ASCII column
        let mut ascii_part = String::new();
        for &byte in line_bytes {
            if (0x20..=0x7E).contains(&byte) {
                let _ = write!(ascii_part, "{}", byte as char);
            } else {
                ascii_part.push('.');
            }
        }

        writeln!(writer, "{} {}", hex_part, ascii_part.dimmed())?;
    }

    // Legend
    render_legend(writer, spans)?;

    Ok(())
}

fn find_span<'a>(offset: usize, spans: &[(LayerSpan, &'a str)]) -> Option<&'a str> {
    spans.iter().find_map(|(span, protocol)| {
        if offset >= span.offset && offset < span.offset + span.len {
            Some(*protocol)
        } else {
            None
        }
    })
}

fn render_legend<W: Write>(writer: &mut W, spans: &[(LayerSpan, &str)]) -> std::io::Result<()> {
    let mut seen = Vec::new();
    let mut legend = String::from("  ");
    for (_, protocol) in spans {
        if !seen.contains(protocol) {
            seen.push(protocol);
            let colored_square = format!("{}", "■".color(color::protocol_color(protocol)));
            let _ = write!(legend, "{colored_square} {protocol}  ");
        }
    }
    writeln!(writer, "{legend}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_hex_dump_for_short_input() {
        colored::control::set_override(false);
        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spans = [(LayerSpan { offset: 0, len: 4 }, "TCP")];
        let mut output = Vec::new();
        render(&mut output, &data, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("0000"));
        assert!(text.contains("..\"3DU"));
    }

    #[test]
    fn renders_legend_with_unique_protocols() {
        colored::control::set_override(false);
        let spans = [
            (LayerSpan { offset: 0, len: 14 }, "Ethernet"),
            (LayerSpan { offset: 14, len: 20 }, "IPv4"),
        ];
        let mut output = Vec::new();
        render_legend(&mut output, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("Ethernet"));
        assert!(text.contains("IPv4"));
    }

    #[test]
    fn empty_data_produces_only_header_and_legend() {
        colored::control::set_override(false);
        let mut output = Vec::new();
        render(&mut output, &[], &[]).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("Hex Dump"));
        assert!(!text.contains("0000"));
    }
}
```

- [ ] **Step 2: Register module in main.rs**

Add `mod hexdump;` to `crates/fireshark-cli/src/main.rs`:

```rust
mod color;
mod detail;
mod hexdump;
mod summary;
mod timestamp;
```

(Also add `mod detail;` now — we'll create the file in the next task.)

- [ ] **Step 3: Run tests**

Run: `cargo test -p fireshark-cli hexdump`
Expected: PASS — 3 tests

- [ ] **Step 4: Commit**

```bash
git add crates/fireshark-cli/src/hexdump.rs crates/fireshark-cli/src/main.rs
git commit -m "feat: add color-coded hex dump module"
```

### Task 5: Create detail module and subcommand

**Files:**
- Create: `crates/fireshark-cli/src/detail.rs`
- Modify: `crates/fireshark-cli/src/main.rs`

- [ ] **Step 1: Create detail.rs**

Create `crates/fireshark-cli/src/detail.rs`:

```rust
use std::io::{self, Write};
use std::path::Path;

use colored::Colorize;
use fireshark_core::{
    ArpLayer, DecodedFrame, EthernetLayer, IcmpDetail, IcmpLayer, Ipv4Layer, Ipv6Layer, Layer,
    LayerSpan, Pipeline, TcpLayer, UdpLayer,
};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::hexdump;
use crate::timestamp;

pub fn run(path: &Path, packet_number: usize) -> Result<(), Box<dyn std::error::Error>> {
    if packet_number == 0 {
        return Err("packet number must be >= 1".into());
    }

    let reader = CaptureReader::open(path)?;
    let index = packet_number - 1;

    let decoded = Pipeline::new(reader, decode_packet)
        .nth(index)
        .ok_or_else(|| format!("packet {packet_number} not found (capture has fewer packets)"))?
        .map_err(|e| format!("decode error at packet {packet_number}: {e}"))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    render_header(&mut out, &decoded, packet_number)?;
    render_layer_tree(&mut out, &decoded)?;

    let span_colors: Vec<(LayerSpan, &str)> = decoded
        .packet()
        .layers()
        .iter()
        .zip(decoded.packet().spans())
        .map(|(layer, span)| (*span, layer.name()))
        .collect();
    hexdump::render(&mut out, decoded.frame().data(), &span_colors)?;

    Ok(())
}

fn render_header<W: Write>(
    w: &mut W,
    decoded: &DecodedFrame,
    packet_number: usize,
) -> io::Result<()> {
    let len = decoded.frame().captured_len();
    let ts = match decoded.frame().timestamp() {
        Some(d) => timestamp::format_utc(d),
        None => String::from("-"),
    };
    writeln!(w, "Packet {packet_number} · {len} bytes · {ts}")?;
    writeln!(w, "─────────────────────────────────────────────────")
}

fn render_layer_tree<W: Write>(w: &mut W, decoded: &DecodedFrame) -> io::Result<()> {
    for layer in decoded.packet().layers() {
        render_layer(w, layer)?;
    }
    for issue in decoded.packet().issues() {
        let kind = match issue.kind() {
            fireshark_core::DecodeIssueKind::Truncated => "Truncated",
            fireshark_core::DecodeIssueKind::Malformed => "Malformed",
        };
        writeln!(w, "{} {} at offset {}", "⚠".red(), kind, issue.offset())?;
    }
    Ok(())
}

fn render_layer<W: Write>(w: &mut W, layer: &Layer) -> io::Result<()> {
    match layer {
        Layer::Unknown => {
            writeln!(w, "{}", "▸ Unknown".color(color::protocol_color("Unknown")))
        }
        Layer::Ethernet(l) => render_ethernet(w, l),
        Layer::Arp(l) => render_arp(w, l),
        Layer::Ipv4(l) => render_ipv4(w, l),
        Layer::Ipv6(l) => render_ipv6(w, l),
        Layer::Tcp(l) => render_tcp(w, l),
        Layer::Udp(l) => render_udp(w, l),
        Layer::Icmp(l) => render_icmp(w, l),
    }
}

fn render_ethernet<W: Write>(w: &mut W, l: &EthernetLayer) -> io::Result<()> {
    writeln!(
        w,
        "{}",
        "▸ Ethernet".color(color::protocol_color("Ethernet"))
    )?;
    writeln!(w, "    Destination: {}", format_mac(l.destination))?;
    writeln!(w, "    Source:      {}", format_mac(l.source))?;
    writeln!(
        w,
        "    EtherType:   0x{:04x} ({})",
        l.ether_type,
        ether_type_name(l.ether_type)
    )
}

fn render_arp<W: Write>(w: &mut W, l: &ArpLayer) -> io::Result<()> {
    let op = match l.operation {
        1 => "request",
        2 => "reply",
        _ => "unknown",
    };
    writeln!(w, "{}", "▸ ARP".color(color::protocol_color("ARP")))?;
    writeln!(w, "    Operation:  {} ({})", l.operation, op)?;
    writeln!(w, "    Sender IP:  {}", l.sender_protocol_addr)?;
    writeln!(w, "    Target IP:  {}", l.target_protocol_addr)
}

fn render_ipv4<W: Write>(w: &mut W, l: &Ipv4Layer) -> io::Result<()> {
    writeln!(w, "{}", "▸ IPv4".color(color::protocol_color("IPv4")))?;
    writeln!(w, "    Source:      {}", l.source)?;
    writeln!(w, "    Destination: {}", l.destination)?;
    let mut flags = Vec::new();
    if l.dont_fragment {
        flags.push("DF");
    }
    if l.more_fragments {
        flags.push("MF");
    }
    let flag_str = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("] ["))
    };
    writeln!(
        w,
        "    TTL: {}  Protocol: {} ({})  ID: 0x{:04x}{}",
        l.ttl,
        l.protocol,
        ip_protocol_name(l.protocol),
        l.identification,
        flag_str
    )?;
    writeln!(
        w,
        "    DSCP: {}  ECN: {}  Checksum: 0x{:04x}",
        l.dscp, l.ecn, l.header_checksum
    )
}

fn render_ipv6<W: Write>(w: &mut W, l: &Ipv6Layer) -> io::Result<()> {
    writeln!(w, "{}", "▸ IPv6".color(color::protocol_color("IPv6")))?;
    writeln!(w, "    Source:      {}", l.source)?;
    writeln!(w, "    Destination: {}", l.destination)?;
    writeln!(
        w,
        "    Next Header: {} ({})  Hop Limit: {}",
        l.next_header,
        ip_protocol_name(l.next_header),
        l.hop_limit
    )?;
    writeln!(
        w,
        "    Traffic Class: {}  Flow Label: {}",
        l.traffic_class, l.flow_label
    )
}

fn render_tcp<W: Write>(w: &mut W, l: &TcpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ TCP".color(color::protocol_color("TCP")))?;
    let mut flags = Vec::new();
    if l.flags.syn {
        flags.push("SYN");
    }
    if l.flags.ack {
        flags.push("ACK");
    }
    if l.flags.fin {
        flags.push("FIN");
    }
    if l.flags.rst {
        flags.push("RST");
    }
    if l.flags.psh {
        flags.push("PSH");
    }
    if l.flags.urg {
        flags.push("URG");
    }
    if l.flags.ece {
        flags.push("ECE");
    }
    if l.flags.cwr {
        flags.push("CWR");
    }
    let flag_str = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("] ["))
    };
    writeln!(
        w,
        "    {} → {}  Seq: {}  Ack: {}{}  Win: {}",
        l.source_port, l.destination_port, l.seq, l.ack, flag_str, l.window
    )?;
    writeln!(
        w,
        "    Data Offset: {} ({} bytes)",
        l.data_offset,
        usize::from(l.data_offset) * 4
    )
}

fn render_udp<W: Write>(w: &mut W, l: &UdpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ UDP".color(color::protocol_color("UDP")))?;
    writeln!(
        w,
        "    {} → {}  Length: {}",
        l.source_port, l.destination_port, l.length
    )
}

fn render_icmp<W: Write>(w: &mut W, l: &IcmpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ ICMP".color(color::protocol_color("ICMP")))?;
    writeln!(
        w,
        "    Type: {} ({})  Code: {}",
        l.type_,
        icmp_type_name(l.type_),
        l.code
    )?;
    match l.detail {
        Some(IcmpDetail::EchoRequest {
            identifier,
            sequence,
        }) => writeln!(w, "    Identifier: 0x{identifier:04x}  Sequence: {sequence}"),
        Some(IcmpDetail::EchoReply {
            identifier,
            sequence,
        }) => writeln!(w, "    Identifier: 0x{identifier:04x}  Sequence: {sequence}"),
        Some(IcmpDetail::DestinationUnreachable { next_hop_mtu }) => {
            writeln!(w, "    Next Hop MTU: {next_hop_mtu}")
        }
        Some(IcmpDetail::Other { rest_of_header }) => {
            writeln!(w, "    Rest of Header: 0x{rest_of_header:08x}")
        }
        None => Ok(()),
    }
}

fn format_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn ether_type_name(ether_type: u16) -> &'static str {
    match ether_type {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        _ => "Unknown",
    }
}

fn ip_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Unknown",
    }
}

fn icmp_type_name(type_: u8) -> &'static str {
    match type_ {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        128 => "Echo Request (v6)",
        129 => "Echo Reply (v6)",
        _ => "Unknown",
    }
}
```

- [ ] **Step 2: Update main.rs with detail subcommand**

Replace `crates/fireshark-cli/src/main.rs`:

```rust
mod color;
mod detail;
mod hexdump;
mod summary;
mod timestamp;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "fireshark")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Summary {
        path: PathBuf,
    },
    Detail {
        path: PathBuf,
        #[arg(help = "Packet number (1-indexed)")]
        packet: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Summary { path } => summary::run(&path)?,
        Command::Detail { path, packet } => detail::run(&path, packet)?,
    }

    Ok(())
}
```

- [ ] **Step 3: Run all CLI tests**

Run: `cargo test -p fireshark-cli`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/fireshark-cli/src/detail.rs crates/fireshark-cli/src/main.rs
git commit -m "feat: add detail subcommand with layer tree and hex dump"
```

### Task 6: Add integration tests

**Files:**
- Create: `crates/fireshark-cli/tests/detail_command.rs`

- [ ] **Step 1: Create integration tests**

Create `crates/fireshark-cli/tests/detail_command.rs`:

```rust
mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn detail_command_shows_layer_tree_and_hex() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("1");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("IPv4"))
        .stdout(contains("TCP"))
        .stdout(contains("51514"))
        .stdout(contains("443"))
        .stdout(contains("[SYN]"))
        .stdout(contains("0000"))
        .stdout(contains("Hex Dump"));
}

#[test]
fn detail_command_fails_for_out_of_range_packet() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("999");
    cmd.assert().failure();
}

#[test]
fn detail_command_fails_for_zero_packet_number() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("0");
    cmd.assert().failure();
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test -p fireshark-cli detail_command`
Expected: PASS — 3 tests

- [ ] **Step 3: Run just check**

Run: `just check`
Expected: PASS

- [ ] **Step 4: Smoke test**

Run: `cargo run -p fireshark-cli -- detail fixtures/smoke/minimal.pcap 1`
Expected: Colored layer tree + hex dump output

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-cli/tests/detail_command.rs
git commit -m "test: add integration tests for detail command"
```
