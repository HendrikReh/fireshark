# DNS Dissector Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a DNS protocol dissector with application-layer dispatch, wired through all 6 crates (core, dissectors, filter, cli, mcp).

**Architecture:** New `DnsLayer` in core, `dns.rs` dissector dispatched by UDP port 53 via a new `append_application_layer` function, DNS name parsing with label-length encoding, filter fields, CLI color/detail, MCP view.

**Tech Stack:** Rust, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-16-dns-dissector-design.md`

---

## Chunk 1: Core type + dissector + fixture

### Task 1: Add `DnsLayer` to fireshark-core

**File:** `crates/fireshark-core/src/layer.rs`

- [ ] Add `DnsLayer` struct after `IcmpLayer`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLayer {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub query_name: Option<String>,
    pub query_type: Option<u16>,
}
```

- [ ] Add `Dns(DnsLayer)` variant to the `Layer` enum (after `Icmp`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    Unknown,
    Ethernet(EthernetLayer),
    Arp(ArpLayer),
    Ipv4(Ipv4Layer),
    Ipv6(Ipv6Layer),
    Tcp(TcpLayer),
    Udp(UdpLayer),
    Icmp(IcmpLayer),
    Dns(DnsLayer),
}
```

- [ ] Add `"DNS"` arm to `Layer::name()`:

```rust
impl Layer {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Ethernet(_) => "Ethernet",
            Self::Arp(_) => "ARP",
            Self::Ipv4(_) => "IPv4",
            Self::Ipv6(_) => "IPv6",
            Self::Tcp(_) => "TCP",
            Self::Udp(_) => "UDP",
            Self::Icmp(_) => "ICMP",
            Self::Dns(_) => "DNS",
        }
    }
}
```

**File:** `crates/fireshark-core/src/lib.rs`

- [ ] Add `DnsLayer` to the re-export list:

```rust
pub use layer::{
    ArpLayer, DnsLayer, EthernetLayer, IcmpDetail, IcmpLayer, Ipv4Layer, Ipv6Layer, Layer,
    TcpFlags, TcpLayer, UdpLayer,
};
```

### Task 2: Create `dns.rs` dissector module

**New file:** `crates/fireshark-dissectors/src/dns.rs`

- [ ] Create the file with constants, `parse` function, and `parse_name` helper:

```rust
use fireshark_core::{DnsLayer, Layer};

use crate::DecodeError;

pub const UDP_PORT: u16 = 53;
pub const TCP_PORT: u16 = 53;
const HEADER_LEN: usize = 12;

/// Maximum number of labels to prevent malicious deeply nested names.
const MAX_LABELS: usize = 128;

/// Maximum total name length per RFC 1035.
const MAX_NAME_LEN: usize = 255;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "DNS",
            offset: offset + bytes.len(),
        });
    }

    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let question_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    // authority_count and additional_count read but not stored
    let _authority_count = u16::from_be_bytes([bytes[8], bytes[9]]);
    let _additional_count = u16::from_be_bytes([bytes[10], bytes[11]]);

    // Attempt to parse the first question entry
    let (query_name, query_type) = if question_count > 0 {
        parse_question(bytes)
    } else {
        (None, None)
    };

    Ok(Layer::Dns(DnsLayer {
        transaction_id,
        is_response,
        opcode,
        question_count,
        answer_count,
        query_name,
        query_type,
    }))
}

/// Parse the first question entry from the DNS message.
/// Returns (query_name, query_type) — both None if parsing fails.
fn parse_question(bytes: &[u8]) -> (Option<String>, Option<u16>) {
    let Some((name, consumed)) = parse_name(bytes, HEADER_LEN) else {
        return (None, None);
    };

    let qtype_start = HEADER_LEN + consumed;
    // Need 4 bytes for qtype (2) + qclass (2)
    if qtype_start + 4 > bytes.len() {
        return (None, None);
    }

    let query_type = u16::from_be_bytes([bytes[qtype_start], bytes[qtype_start + 1]]);
    // qclass read but not stored
    let _query_class = u16::from_be_bytes([bytes[qtype_start + 2], bytes[qtype_start + 3]]);

    let query_name = if name.is_empty() { None } else { Some(name) };
    (query_name, Some(query_type))
}

/// Parse a DNS name using label-length encoding.
///
/// Returns `Some((name, bytes_consumed))` on success, `None` on failure.
/// `bytes_consumed` counts bytes from `start` through the terminating zero
/// (or up to a compression pointer, which terminates parsing).
fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut total_len: usize = 0;

    for _ in 0..MAX_LABELS {
        if pos >= bytes.len() {
            return None;
        }

        let n = bytes[pos];

        if n == 0 {
            // End of name
            let consumed = pos - start + 1; // +1 for the zero byte
            let name = labels.join(".");
            return Some((name, consumed));
        }

        if n & 0xC0 == 0xC0 {
            // Compression pointer — stop parsing, return what we have
            // (don't follow pointers in v1)
            let name = labels.join(".");
            // If nothing was accumulated before the pointer, return empty
            // which the caller converts to None
            let consumed = pos - start + 2; // pointer is 2 bytes
            if pos + 1 >= bytes.len() {
                return None; // pointer byte missing
            }
            return Some((name, consumed));
        }

        if n > 63 {
            // Invalid label length
            return None;
        }

        let label_len = n as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;

        if label_end > bytes.len() {
            return None; // truncated
        }

        total_len += label_len + 1; // +1 for the length byte (or dot separator)
        if total_len > MAX_NAME_LEN {
            return None;
        }

        let label = String::from_utf8_lossy(&bytes[label_start..label_end]).into_owned();
        labels.push(label);
        pos = label_end;
    }

    // Exceeded max labels
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_simple() {
        // "example.com" = 07 "example" 03 "com" 00
        let data = b"\x07example\x03com\x00";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 13); // 1+7+1+3+1
    }

    #[test]
    fn parse_name_with_compression_pointer() {
        // "www" then compression pointer 0xC00C
        let data = b"\x03www\xC0\x0C";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "www");
        assert_eq!(consumed, 6); // 1+3+2
    }

    #[test]
    fn parse_name_only_pointer_yields_empty() {
        let data = b"\xC0\x0C";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_name_truncated_returns_none() {
        let data = b"\x07exam"; // says 7 bytes but only 4
        assert!(parse_name(data, 0).is_none());
    }

    #[test]
    fn parse_name_invalid_label_length() {
        let data = b"\x80invalid"; // 0x80 has top bit set but not both top bits
        assert!(parse_name(data, 0).is_none());
    }
}
```

**Key details:**
- `parse_name` returns `Some(("", consumed))` when a compression pointer is the first thing encountered. The caller in `parse_question` converts empty strings to `None` for `query_name`.
- Safety limits: max 128 labels, max 255 total name bytes, all slice accesses bounds-checked.
- No `DecodeError::Malformed` for unparseable question sections — optional fields just become `None`.

### Task 3: Create fixture file

**New file:** `fixtures/bytes/ethernet_ipv4_udp_dns.bin`

- [ ] Create a Python script to generate the fixture, then run it:

```python
#!/usr/bin/env python3
"""Generate ethernet_ipv4_udp_dns.bin fixture (71 bytes)."""
import struct, sys

# Ethernet header (14 bytes)
eth_dst = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
eth_src = bytes([0x66, 0x77, 0x88, 0x99, 0x0a, 0xbb])
eth_type = struct.pack("!H", 0x0800)
ethernet = eth_dst + eth_src + eth_type  # 14 bytes

# DNS payload (29 bytes: 12 header + 17 question)
dns_txid = struct.pack("!H", 0x1234)
dns_flags = struct.pack("!H", 0x0100)  # QR=0, Opcode=0, RD=1
dns_qdcount = struct.pack("!H", 1)
dns_ancount = struct.pack("!H", 0)
dns_nscount = struct.pack("!H", 0)
dns_arcount = struct.pack("!H", 0)
dns_header = dns_txid + dns_flags + dns_qdcount + dns_ancount + dns_nscount + dns_arcount  # 12 bytes

# Question: example.com type A class IN
# 07 "example" 03 "com" 00 0001 0001
dns_question = (
    b"\x07example\x03com\x00"  # 13 bytes
    + struct.pack("!HH", 1, 1)  # type=A(1), class=IN(1) — 4 bytes
)  # 17 bytes

dns_payload = dns_header + dns_question  # 29 bytes

# UDP header (8 bytes)
udp_src_port = struct.pack("!H", 12345)
udp_dst_port = struct.pack("!H", 53)
udp_length = struct.pack("!H", 8 + len(dns_payload))  # 37
udp_checksum = struct.pack("!H", 0)
udp = udp_src_port + udp_dst_port + udp_length + udp_checksum  # 8 bytes

# IPv4 header (20 bytes)
ip_payload = udp + dns_payload  # 37 bytes
ip_total_len = 20 + len(ip_payload)  # 57
ipv4 = struct.pack("!BBHHHBBH4s4s",
    0x45,           # version=4, ihl=5
    0x00,           # DSCP=0, ECN=0
    ip_total_len,   # total length = 57
    0x0000,         # identification
    0x4000,         # flags=DF, fragment offset=0
    64,             # TTL
    17,             # protocol = UDP
    0x0000,         # header checksum (0 for fixture)
    bytes([192, 0, 2, 10]),     # src = 192.0.2.10
    bytes([198, 51, 100, 20]),  # dst = 198.51.100.20
)  # 20 bytes

frame = ethernet + ipv4 + udp + dns_payload
assert len(frame) == 71, f"Expected 71 bytes, got {len(frame)}"

sys.stdout.buffer.write(frame)
```

- [ ] Run: `python3 gen_dns_fixture.py > fixtures/bytes/ethernet_ipv4_udp_dns.bin`
- [ ] Verify: `xxd fixtures/bytes/ethernet_ipv4_udp_dns.bin | head -5` — should be 71 bytes
- [ ] Delete the Python script after generating the fixture

**Expected hex dump (71 bytes):**
```
Offset  Hex
00-0d   00 11 22 33 44 55 66 77 88 99 0a bb 08 00          (Ethernet, 14 bytes)
0e-21   45 00 00 39 00 00 40 00 40 11 00 00 c0 00 02 0a    (IPv4, 20 bytes)
        c6 33 64 14
22-29   30 39 00 35 00 25 00 00                              (UDP, 8 bytes)
2a-46   12 34 01 00 00 01 00 00 00 00 00 00                  (DNS header, 12 bytes)
        07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01  (DNS question, 17 bytes)
```

### Task 4: Wire DNS into decode pipeline

**File:** `crates/fireshark-dissectors/src/lib.rs`

- [ ] Add `mod dns;` to the module list (after `mod udp;`):

```rust
mod arp;
mod dns;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;
```

- [ ] Add new `append_application_layer` function after `transport_span`:

```rust
fn append_application_layer(
    transport: &Layer,
    app_payload: &[u8],
    app_offset: usize,
    layers: &mut Vec<Layer>,
    spans: &mut Vec<LayerSpan>,
    issues: &mut Vec<DecodeIssue>,
) {
    // Extract ports from UDP only (TCP DNS not supported in v1)
    let (src_port, dst_port) = match transport {
        Layer::Udp(udp) => (udp.source_port, udp.destination_port),
        _ => return,
    };

    if src_port == dns::UDP_PORT || dst_port == dns::UDP_PORT {
        let span = LayerSpan {
            offset: app_offset,
            len: app_payload.len(),
        };
        append_layer_with_span(
            dns::parse(app_payload, app_offset),
            app_offset,
            span,
            layers,
            spans,
            issues,
        );
    }
}
```

- [ ] Modify `append_network_layer` to call `append_application_layer` after transport decode succeeds. Inside the `Ok(NetworkPayload { .. })` arm, after the `match protocol` block, add:

```rust
// After the transport match block, attempt application-layer dispatch.
// Compute app_payload from the last span pushed (the transport span).
if let Some(last_transport) = layers.last() {
    if let Some(last_span) = spans.last() {
        let transport_end = last_span.offset + last_span.len;
        if transport_end > payload_offset && transport_end - payload_offset <= payload.len()
        {
            let app_payload = &payload[transport_end - payload_offset..];
            if !app_payload.is_empty() {
                append_application_layer(
                    last_transport,
                    app_payload,
                    transport_end,
                    layers,
                    spans,
                    issues,
                );
            }
        }
    }
}
```

**Full updated `append_network_layer`** for clarity — the transport match block remains unchanged, and the application-layer dispatch is appended right after it, still within the `Ok(NetworkPayload { .. })` arm:

```rust
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
            let parse_transport =
                |result: Result<Layer, DecodeError>,
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
                    parse_transport(tcp::parse(payload, payload_offset), layers, spans, issues);
                }
                udp::IP_PROTOCOL => {
                    parse_transport(udp::parse(payload, payload_offset), layers, spans, issues);
                }
                icmp::IPV4_PROTOCOL | icmp::IPV6_PROTOCOL => {
                    parse_transport(icmp::parse(payload, payload_offset), layers, spans, issues);
                }
                _ => {}
            }

            // Application-layer dispatch: attempt to decode protocols above transport.
            if let Some(last_transport) = layers.last() {
                if let Some(last_span) = spans.last() {
                    let transport_end = last_span.offset + last_span.len;
                    if transport_end > payload_offset
                        && transport_end - payload_offset <= payload.len()
                    {
                        let app_payload = &payload[transport_end - payload_offset..];
                        if !app_payload.is_empty() {
                            append_application_layer(
                                last_transport,
                                app_payload,
                                transport_end,
                                layers,
                                spans,
                                issues,
                            );
                        }
                    }
                }
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

**Why this computation works:** After transport decode, `spans.last()` is the transport span (e.g., UDP at offset 34, len 8). `transport_end = 34 + 8 = 42`. The IP `payload` starts at `payload_offset = 34`. So `app_payload = &payload[42 - 34..] = &payload[8..]`, which is the bytes after the UDP header — exactly the DNS message. `app_offset = 42` is the absolute frame offset where DNS begins.

### Task 5: Dissector tests

**New file:** `crates/fireshark-dissectors/tests/dns.rs`

- [ ] Create test file:

```rust
use fireshark_core::{Layer, LayerSpan};
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_dns_query() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();

    let dns = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Dns(layer) => Some(layer),
            _ => None,
        })
        .expect("DNS layer");

    assert_eq!(dns.transaction_id, 0x1234);
    assert!(!dns.is_response);
    assert_eq!(dns.opcode, 0);
    assert_eq!(dns.question_count, 1);
    assert_eq!(dns.answer_count, 0);
    assert_eq!(dns.query_name.as_deref(), Some("example.com"));
    assert_eq!(dns.query_type, Some(1)); // A record
}

#[test]
fn decodes_dns_layer_names() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();

    let names: Vec<&str> = packet.layers().iter().map(|l| l.name()).collect();
    assert_eq!(names, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
}

#[test]
fn dns_truncated_header() {
    // Full fixture is 71 bytes. Ethernet(14) + IPv4(20) + UDP(8) = 42 bytes of headers.
    // DNS starts at offset 42. Give only 6 bytes of DNS (need 12).
    // We modify the IPv4 total_len so the IP payload is shorter.
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin").to_vec();

    // Set IPv4 total_len = 20 + 8 + 6 = 34 (only 6 bytes of DNS payload)
    let short_total: u16 = 34;
    bytes[16] = (short_total >> 8) as u8;
    bytes[17] = (short_total & 0xFF) as u8;

    let packet = decode_packet(&bytes).unwrap();

    // Should have Ethernet + IPv4 + UDP but NO DNS (truncated)
    assert!(packet.layer_names().contains(&"UDP"));
    assert!(!packet.layer_names().contains(&"DNS"));
    // Should have a truncation issue
    assert!(!packet.issues().is_empty());
}

#[test]
fn dns_with_compression_pointer_yields_none_name() {
    // Build a minimal DNS message where the question name starts with a compression pointer.
    // 12-byte header + pointer(2) + qtype(2) + qclass(2) = 18 bytes DNS payload
    let dns_bytes: Vec<u8> = vec![
        // DNS header (12 bytes)
        0xAB, 0xCD, // transaction_id
        0x01, 0x00, // flags: query, RD=1
        0x00, 0x01, // qdcount=1
        0x00, 0x00, // ancount=0
        0x00, 0x00, // nscount=0
        0x00, 0x00, // arcount=0
        // Question: compression pointer 0xC00C, type=A, class=IN
        0xC0, 0x0C, // pointer to offset 12 (doesn't matter, we don't follow)
        0x00, 0x01, // type=A
        0x00, 0x01, // class=IN
    ];

    // parse directly (not through full pipeline)
    let layer = fireshark_dissectors::decode_packet(&build_dns_frame(&dns_bytes)).unwrap();
    let dns = layer
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Dns(d) => Some(d),
            _ => None,
        })
        .expect("DNS layer");

    // Compression pointer at start means empty name -> None
    assert_eq!(dns.query_name, None);
    assert_eq!(dns.query_type, Some(1));
}

#[test]
fn dns_span_covers_full_payload() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();

    assert_eq!(spans.len(), 4, "Ethernet + IPv4 + UDP + DNS");

    // DNS span: starts after UDP header (offset 42), covers remaining 29 bytes
    assert_eq!(
        spans[3],
        LayerSpan {
            offset: 42,
            len: 29
        }
    );
}

/// Helper: wrap raw DNS bytes in Ethernet + IPv4 + UDP headers.
fn build_dns_frame(dns_payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0x0a, 0xbb]); // src
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let ip_total_len = (20 + 8 + dns_payload.len()) as u16;
    frame.push(0x45); // version=4, ihl=5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&ip_total_len.to_be_bytes()); // total length
    frame.extend_from_slice(&[0x00, 0x00]); // identification
    frame.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag_offset=0
    frame.push(64); // TTL
    frame.push(17); // protocol=UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(&[192, 0, 2, 10]); // src IP
    frame.extend_from_slice(&[198, 51, 100, 20]); // dst IP

    // UDP header (8 bytes)
    let udp_len = (8 + dns_payload.len()) as u16;
    frame.extend_from_slice(&12345u16.to_be_bytes()); // src port
    frame.extend_from_slice(&53u16.to_be_bytes()); // dst port
    frame.extend_from_slice(&udp_len.to_be_bytes()); // length
    frame.extend_from_slice(&[0x00, 0x00]); // checksum

    // DNS payload
    frame.extend_from_slice(dns_payload);

    frame
}
```

**File:** `crates/fireshark-dissectors/tests/transport.rs`

- [ ] Add `decode_packet_produces_dns_spans` test at the end:

```rust
#[test]
fn decode_packet_produces_dns_spans() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin");
    let packet = decode_packet(bytes).unwrap();
    let spans = packet.spans();
    assert_eq!(spans.len(), 4, "Ethernet + IPv4 + UDP + DNS");
    assert_eq!(spans[0], LayerSpan { offset: 0, len: 14 }); // Ethernet
    assert_eq!(
        spans[1],
        LayerSpan {
            offset: 14,
            len: 20
        }
    ); // IPv4
    assert_eq!(
        spans[2],
        LayerSpan {
            offset: 34,
            len: 8
        }
    ); // UDP
    assert_eq!(
        spans[3],
        LayerSpan {
            offset: 42,
            len: 29
        }
    ); // DNS
}
```

- [ ] Run `just check` — should pass with Chunk 1 complete

---

## Chunk 2: Filter integration

### Task 6: Add `Protocol::Dns` to filter AST, lexer, and parser

**File:** `crates/fireshark-filter/src/ast.rs`

- [ ] Add `Dns` variant to `Protocol` enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Arp,
    Icmp,
    Ipv4,
    Ipv6,
    Ethernet,
    Dns,
}
```

**File:** `crates/fireshark-filter/src/lexer.rs`

- [ ] Add `Dns` token variant to `Token` enum (after `Ethernet`):

```rust
pub enum Token {
    // ... existing variants ...
    Ethernet,
    Dns,
    // ... rest ...
}
```

- [ ] Add `"dns"` to keyword table in `scan_identifier`:

```rust
"eth" | "ethernet" => Token::Ethernet,
"dns" => Token::Dns,
```

**File:** `crates/fireshark-filter/src/parser.rs`

- [ ] Add `Token::Dns` arm in `parse_atom` (after `Token::Ethernet`):

```rust
Token::Dns => {
    cursor.advance();
    Ok(Expr::HasProtocol(Protocol::Dns))
}
```

### Task 7: Add DNS fields to evaluator

**File:** `crates/fireshark-filter/src/evaluate.rs`

- [ ] Add `Protocol::Dns` arm to `has_protocol`:

```rust
Protocol::Dns => matches!(layer, Layer::Dns(_)),
```

- [ ] Add DNS fields to `resolve_layer_field`, after the Ethernet section:

```rust
// DNS
("dns.id", Layer::Dns(l)) => {
    return Some(FieldValue::Integer(u64::from(l.transaction_id)));
}
("dns.qr", Layer::Dns(l)) => return Some(FieldValue::Bool(l.is_response)),
("dns.opcode", Layer::Dns(l)) => {
    return Some(FieldValue::Integer(u64::from(l.opcode)));
}
("dns.qcount", Layer::Dns(l)) => {
    return Some(FieldValue::Integer(u64::from(l.question_count)));
}
("dns.acount", Layer::Dns(l)) => {
    return Some(FieldValue::Integer(u64::from(l.answer_count)));
}
("dns.qtype", Layer::Dns(l)) => {
    return l.query_type.map(|t| FieldValue::Integer(u64::from(t)));
}
```

**Important:** `dns.qtype` returns `Option` — when `query_type` is `None`, `resolve_layer_field` returns `None` and comparisons evaluate to `false`. This is handled naturally because the `return l.query_type.map(...)` expression returns `None` when `query_type` is `None`, and the for loop continues to check other layers. If no layer matches, the function returns `None`, and `compare_field` returns `false`.

- [ ] Add tests to `crates/fireshark-filter/src/evaluate.rs` (in the `mod tests` block):

```rust
// --- DNS fixture: ethernet_ipv4_udp_dns.bin ---
// Layers: Ethernet + IPv4 + UDP(12345→53) + DNS(txid=0x1234, query, example.com A)

#[test]
fn has_protocol_dns_on_dns_packet() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns", &decoded));
}

#[test]
fn has_protocol_dns_on_tcp_packet_is_false() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
    ));
    assert!(!run_filter("dns", &decoded));
}

#[test]
fn dns_id_field() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.id == 4660", &decoded)); // 0x1234 = 4660
}

#[test]
fn dns_qr_bare_field_is_false_for_query() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    // is_response = false for a query, so bare dns.qr returns false
    assert!(!run_filter("dns.qr", &decoded));
}

#[test]
fn dns_qr_eq_false_matches_query() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.qr == false", &decoded));
}

#[test]
fn dns_qcount_field() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.qcount == 1", &decoded));
}

#[test]
fn dns_acount_field() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.acount == 0", &decoded));
}

#[test]
fn dns_qtype_field() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.qtype == 1", &decoded)); // A record
}

#[test]
fn dns_opcode_field() {
    let decoded = decoded_from_bytes(include_bytes!(
        "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
    ));
    assert!(run_filter("dns.opcode == 0", &decoded)); // standard query
}
```

- [ ] Run `just check` — should pass with Chunk 2 complete

---

## Chunk 3: CLI + MCP

### Task 8: Add DNS color

**File:** `crates/fireshark-cli/src/color.rs`

- [ ] Add DNS → Magenta before the else/Unknown fallback. Change:

```rust
    } else if protocol.eq_ignore_ascii_case("ipv4")
        || protocol.eq_ignore_ascii_case("ipv6")
        || protocol.eq_ignore_ascii_case("ethernet")
    {
        Color::White
    } else {
```

to:

```rust
    } else if protocol.eq_ignore_ascii_case("dns") {
        Color::Magenta
    } else if protocol.eq_ignore_ascii_case("ipv4")
        || protocol.eq_ignore_ascii_case("ipv6")
        || protocol.eq_ignore_ascii_case("ethernet")
    {
        Color::White
    } else {
```

- [ ] Add test:

```rust
#[test]
fn dns_lines_are_magenta() {
    let cs = colorize("DNS", "test line");
    assert_eq!(cs.fgcolor, Some(Color::Magenta));
}
```

### Task 9: Add DNS detail rendering

**File:** `crates/fireshark-cli/src/detail.rs`

- [ ] Add `DnsLayer` to the import line:

```rust
use fireshark_core::{
    ArpLayer, DecodedFrame, DnsLayer, EthernetLayer, IcmpDetail, IcmpLayer, Ipv4Layer,
    Ipv6Layer, Layer, LayerSpan, Pipeline, TcpLayer, UdpLayer,
};
```

- [ ] Add `Layer::Dns` arm to `render_layer`:

```rust
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
        Layer::Dns(l) => render_dns(w, l),
    }
}
```

- [ ] Add `render_dns` function and `dns_qtype_name` helper:

```rust
fn render_dns<W: Write>(w: &mut W, l: &DnsLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ DNS".color(color::protocol_color("DNS")))?;
    let direction = if l.is_response { "Response" } else { "Query" };
    writeln!(
        w,
        "    Transaction ID: 0x{:04x}  [{}]",
        l.transaction_id, direction
    )?;
    writeln!(
        w,
        "    Questions: {}  Answers: {}",
        l.question_count, l.answer_count
    )?;
    match (&l.query_name, l.query_type) {
        (Some(name), Some(qtype)) => {
            writeln!(w, "    Query: {} ({})", name, dns_qtype_name(qtype))
        }
        (Some(name), None) => writeln!(w, "    Query: {}", name),
        (None, _) => writeln!(w, "    Query: <unparseable>"),
    }
}

fn dns_qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "Unknown",
    }
}
```

### Task 10: Add DNS to MCP model

**File:** `crates/fireshark-mcp/src/model.rs`

- [ ] Add `Dns` variant to `LayerView` enum (after `Icmp`):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum LayerView {
    // ... existing variants ...
    #[serde(rename = "ICMP")]
    Icmp {
        type_: u8,
        code: u8,
        detail: Option<IcmpDetailView>,
    },
    #[serde(rename = "DNS")]
    Dns {
        transaction_id: u16,
        is_response: bool,
        opcode: u8,
        question_count: u16,
        answer_count: u16,
        query_name: Option<String>,
        query_type: Option<u16>,
    },
}
```

- [ ] Add `Layer::Dns` arm to `LayerView::from_layer` (after the `Layer::Icmp` arm):

```rust
Layer::Dns(layer) => Self::Dns {
    transaction_id: layer.transaction_id,
    is_response: layer.is_response,
    opcode: layer.opcode,
    question_count: layer.question_count,
    answer_count: layer.answer_count,
    query_name: layer.query_name.clone(),
    query_type: layer.query_type,
},
```

- [ ] Run `just check` — should pass with Chunk 3 complete

---

## Chunk 4: Integration tests + verification

### Task 11: CLI integration test

**File:** `crates/fireshark-cli/tests/cli.rs` (or existing integration test file)

- [ ] Verify that the fuzz fixture has UDP port 53 traffic: `fireshark summary fixtures/smoke/fuzz-fixture.pcap -f "dns"` should produce output with DNS packets. If `fuzz-fixture.pcap` does not exist or lacks port 53 traffic, create a pcap from the DNS fixture using a Python script:

```python
#!/usr/bin/env python3
"""Create a minimal pcap wrapping the DNS fixture."""
import struct, sys

# Read the DNS fixture
dns_frame = open("fixtures/bytes/ethernet_ipv4_udp_dns.bin", "rb").read()

# pcap global header
MAGIC = 0xa1b2c3d4
VERSION_MAJOR = 2
VERSION_MINOR = 4
THISZONE = 0
SIGFIGS = 0
SNAPLEN = 65535
NETWORK = 1  # Ethernet

header = struct.pack("<IHHiIII", MAGIC, VERSION_MAJOR, VERSION_MINOR,
                     THISZONE, SIGFIGS, SNAPLEN, NETWORK)

# pcap packet header
ts_sec = 1000000000
ts_usec = 0
incl_len = len(dns_frame)
orig_len = len(dns_frame)
pkt_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)

sys.stdout.buffer.write(header + pkt_header + dns_frame)
```

- [ ] Add CLI integration test (if not using fuzz fixture):

```rust
#[test]
fn summary_with_dns_filter() {
    Command::cargo_bin("fireshark")
        .unwrap()
        .args(["summary", "fixtures/smoke/dns-query.pcap", "-f", "dns"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DNS"));
}
```

### Task 12: Full verification

- [ ] Run `just check` (fmt-check + clippy + test) — must pass clean
- [ ] Run `just test` — all tests green
- [ ] Smoke test: `cargo run -- summary fixtures/smoke/dns-query.pcap` (or equivalent fixture) should show DNS packets
- [ ] Smoke test: `cargo run -- detail fixtures/smoke/dns-query.pcap 1` should show the DNS layer tree with query name and type

---

## File Summary

### New files (3)
| File | Description |
|------|-------------|
| `crates/fireshark-dissectors/src/dns.rs` | DNS dissector: parse function + name parser |
| `crates/fireshark-dissectors/tests/dns.rs` | DNS dissector unit tests |
| `fixtures/bytes/ethernet_ipv4_udp_dns.bin` | 71-byte handcrafted DNS query fixture |

### Modified files (11)
| File | Change |
|------|--------|
| `crates/fireshark-core/src/layer.rs` | Add `DnsLayer` struct + `Layer::Dns` variant + `"DNS"` in `name()` |
| `crates/fireshark-core/src/lib.rs` | Export `DnsLayer` |
| `crates/fireshark-dissectors/src/lib.rs` | Add `mod dns`, add `append_application_layer`, wire into `append_network_layer` |
| `crates/fireshark-filter/src/ast.rs` | Add `Dns` to `Protocol` enum |
| `crates/fireshark-filter/src/lexer.rs` | Add `Dns` token + `"dns"` keyword |
| `crates/fireshark-filter/src/parser.rs` | Add `Token::Dns` arm |
| `crates/fireshark-filter/src/evaluate.rs` | Add `Protocol::Dns` to `has_protocol`, add `dns.*` fields to `resolve_layer_field` |
| `crates/fireshark-dissectors/tests/transport.rs` | Add `decode_packet_produces_dns_spans` test |
| `crates/fireshark-cli/src/color.rs` | Add `"DNS"` → `Color::Magenta` |
| `crates/fireshark-cli/src/detail.rs` | Add `render_dns` + `dns_qtype_name` + `Layer::Dns` arm |
| `crates/fireshark-mcp/src/model.rs` | Add `Dns` variant to `LayerView` + `from_layer` mapping |
