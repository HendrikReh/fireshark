# Dissector Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract commonly-needed RFC fields from all protocol dissectors, add edge case tests with new fixtures, integrate the orphaned fuzz fixture, and set up cargo-fuzz infrastructure.

**Architecture:** Expand layer structs in `fireshark-core::layer` with new fields, update each dissector's `parse()` function to extract them, fix all downstream consumers (tests, MCP views), then add fuzz targets.

**Tech Stack:** Rust, `cargo-fuzz` with `libFuzzer`, `tempfile` crate (fuzz dev-dep only).

**Spec:** `docs/superpowers/specs/2026-03-16-dissector-hardening-design.md`

---

## Chunk 1: Core type changes

### Task 1: Add TcpFlags and IcmpDetail types to fireshark-core

**Files:**
- Modify: `crates/fireshark-core/src/layer.rs`
- Modify: `crates/fireshark-core/src/lib.rs`

- [ ] **Step 1: Add TcpFlags struct and IcmpDetail enum to layer.rs**

Add after the `use` statement at the top of `crates/fireshark-core/src/layer.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpDetail {
    EchoRequest { identifier: u16, sequence: u16 },
    EchoReply { identifier: u16, sequence: u16 },
    DestinationUnreachable { next_hop_mtu: u16 },
    Other { rest_of_header: u32 },
}
```

- [ ] **Step 2: Expand Ipv4Layer**

Replace the `Ipv4Layer` struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Layer {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub identification: u16,
    pub dscp: u8,
    pub ecn: u8,
    pub dont_fragment: bool,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub header_checksum: u16,
}
```

- [ ] **Step 3: Expand Ipv6Layer**

Replace the `Ipv6Layer` struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Layer {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hop_limit: u8,
}
```

- [ ] **Step 4: Expand TcpLayer**

Replace the `TcpLayer` struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpLayer {
    pub source_port: u16,
    pub destination_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
}
```

- [ ] **Step 5: Expand UdpLayer**

Replace the `UdpLayer` struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpLayer {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
}
```

- [ ] **Step 6: Expand IcmpLayer**

Replace the `IcmpLayer` struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpLayer {
    pub type_: u8,
    pub code: u8,
    pub detail: Option<IcmpDetail>,
}
```

- [ ] **Step 7: Update lib.rs exports**

In `crates/fireshark-core/src/lib.rs`, update the layer export to include the new types:

```rust
pub use layer::{
    ArpLayer, EthernetLayer, IcmpDetail, IcmpLayer, Ipv4Layer, Ipv6Layer, Layer, TcpFlags,
    TcpLayer, UdpLayer,
};
```

- [ ] **Step 8: Verify compilation fails (expected)**

Run: `cargo check --workspace 2>&1 | head -20`
Expected: FAIL — dissectors still construct old struct shapes. This confirms the type changes propagate.

- [ ] **Step 9: Commit**

```bash
git add crates/fireshark-core/src/layer.rs crates/fireshark-core/src/lib.rs
git commit -m "feat: expand layer structs with RFC fields (TcpFlags, IcmpDetail, etc.)"
```

---

## Chunk 2: Dissector updates

### Task 2: Update IPv4 dissector

**Files:**
- Modify: `crates/fireshark-dissectors/src/ipv4.rs`

- [ ] **Step 1: Extract new fields in parse function**

Replace the `Ok(NetworkPayload { ... })` block in `crates/fireshark-dissectors/src/ipv4.rs` (lines 38-62). The full updated `parse` function:

```rust
pub fn parse(bytes: &[u8]) -> Result<NetworkPayload<'_>, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: 14 + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if version != 4 {
        return Err(DecodeError::Malformed("invalid IPv4 version"));
    }
    if header_len < MIN_HEADER_LEN {
        return Err(DecodeError::Malformed("invalid IPv4 header length"));
    }
    if bytes.len() < header_len {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: 14 + bytes.len(),
        });
    }

    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len {
        return Err(DecodeError::Malformed("invalid IPv4 total length"));
    }

    let dscp = bytes[1] >> 2;
    let ecn = bytes[1] & 0x03;
    let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment_bits = u16::from_be_bytes([bytes[6], bytes[7]]);
    let dont_fragment = (fragment_bits & 0x4000) != 0;
    let more_fragments = (fragment_bits & 0x2000) != 0;
    let fragment_offset = fragment_bits & 0x1fff;
    let ttl = bytes[8];
    let protocol = bytes[9];
    let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let payload_end = total_len.min(bytes.len());
    let mut issues = Vec::new();
    if bytes.len() < total_len {
        issues.push(DecodeIssue::truncated(14 + bytes.len()));
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv4(Ipv4Layer {
            source,
            destination,
            protocol,
            ttl,
            identification,
            dscp,
            ecn,
            dont_fragment,
            fragment_offset,
            more_fragments,
            header_checksum,
        }),
        protocol,
        payload: &bytes[header_len..payload_end],
        payload_offset: 14 + header_len,
        issues,
    })
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check -p fireshark-dissectors 2>&1 | head -20`
Expected: Errors from tests constructing old `Ipv4Layer` shape — that's expected, we'll fix tests later.

### Task 3: Update IPv6 dissector

**Files:**
- Modify: `crates/fireshark-dissectors/src/ipv6.rs`

- [ ] **Step 1: Extract new fields**

Replace the layer construction in `crates/fireshark-dissectors/src/ipv6.rs`. Full updated `parse` function:

```rust
pub fn parse(bytes: &[u8]) -> Result<NetworkPayload<'_>, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv6",
            offset: 14 + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(DecodeError::Malformed("invalid IPv6 version"));
    }

    let traffic_class = ((bytes[0] & 0x0F) << 4) | (bytes[1] >> 4);
    let flow_label = u32::from_be_bytes([0, bytes[1] & 0x0F, bytes[2], bytes[3]]);
    let next_header = bytes[6];
    let hop_limit = bytes[7];
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let source =
        Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("valid IPv6 source slice"));
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).expect("valid IPv6 destination slice"));
    let packet_len = HEADER_LEN + payload_len;
    let payload_end = packet_len.min(bytes.len());
    let mut issues = Vec::new();
    if bytes.len() < packet_len {
        issues.push(DecodeIssue::truncated(14 + bytes.len()));
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv6(Ipv6Layer {
            source,
            destination,
            next_header,
            traffic_class,
            flow_label,
            hop_limit,
        }),
        protocol: next_header,
        payload: &bytes[HEADER_LEN..payload_end],
        payload_offset: 14 + HEADER_LEN,
        issues,
    })
}
```

### Task 4: Update TCP dissector

**Files:**
- Modify: `crates/fireshark-dissectors/src/tcp.rs`

- [ ] **Step 1: Update parse function with new fields and data_offset validation**

Replace entire `crates/fireshark-dissectors/src/tcp.rs`:

```rust
use fireshark_core::{Layer, TcpFlags, TcpLayer};

use crate::DecodeError;

pub const IP_PROTOCOL: u8 = 6;
const MIN_HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "TCP",
            offset: offset + bytes.len(),
        });
    }

    let data_offset = bytes[12] >> 4;
    if data_offset < 5 {
        return Err(DecodeError::Malformed("invalid TCP data offset"));
    }
    let header_len = usize::from(data_offset) * 4;
    if bytes.len() < header_len {
        return Err(DecodeError::Truncated {
            layer: "TCP",
            offset: offset + bytes.len(),
        });
    }

    let flag_bits = bytes[13];
    let flags = TcpFlags {
        fin: (flag_bits & 0x01) != 0,
        syn: (flag_bits & 0x02) != 0,
        rst: (flag_bits & 0x04) != 0,
        psh: (flag_bits & 0x08) != 0,
        ack: (flag_bits & 0x10) != 0,
        urg: (flag_bits & 0x20) != 0,
        ece: (flag_bits & 0x40) != 0,
        cwr: (flag_bits & 0x80) != 0,
    };

    Ok(Layer::Tcp(TcpLayer {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        data_offset,
        flags,
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
    }))
}
```

### Task 5: Update UDP dissector

**Files:**
- Modify: `crates/fireshark-dissectors/src/udp.rs`

- [ ] **Step 1: Extract length field**

Replace entire `crates/fireshark-dissectors/src/udp.rs`:

```rust
use fireshark_core::{Layer, UdpLayer};

use crate::DecodeError;

pub const IP_PROTOCOL: u8 = 17;
const HEADER_LEN: usize = 8;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "UDP",
            offset: offset + bytes.len(),
        });
    }

    Ok(Layer::Udp(UdpLayer {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        length: u16::from_be_bytes([bytes[4], bytes[5]]),
    }))
}
```

### Task 6: Update ICMP dissector

**Files:**
- Modify: `crates/fireshark-dissectors/src/icmp.rs`

- [ ] **Step 1: Parse typed detail**

Replace entire `crates/fireshark-dissectors/src/icmp.rs`:

```rust
use fireshark_core::{IcmpDetail, IcmpLayer, Layer};

use crate::DecodeError;

pub const IPV4_PROTOCOL: u8 = 1;
pub const IPV6_PROTOCOL: u8 = 58;
const MIN_HEADER_LEN: usize = 4;
const DETAIL_LEN: usize = 8;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "ICMP",
            offset: offset + bytes.len(),
        });
    }

    let type_ = bytes[0];
    let code = bytes[1];

    let detail = if bytes.len() >= DETAIL_LEN {
        Some(parse_detail(type_, bytes))
    } else {
        None
    };

    Ok(Layer::Icmp(IcmpLayer {
        type_,
        code,
        detail,
    }))
}

fn parse_detail(type_: u8, bytes: &[u8]) -> IcmpDetail {
    let word_hi = u16::from_be_bytes([bytes[4], bytes[5]]);
    let word_lo = u16::from_be_bytes([bytes[6], bytes[7]]);

    match type_ {
        0 => IcmpDetail::EchoReply {
            identifier: word_hi,
            sequence: word_lo,
        },
        3 => IcmpDetail::DestinationUnreachable {
            next_hop_mtu: word_lo,
        },
        8 => IcmpDetail::EchoRequest {
            identifier: word_hi,
            sequence: word_lo,
        },
        _ => IcmpDetail::Other {
            rest_of_header: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        },
    }
}
```

- [ ] **Step 2: Verify all dissectors compile**

Run: `cargo check -p fireshark-dissectors 2>&1 | head -20`
Expected: May fail on tests that construct old layer shapes — that's fine, we fix those next.

- [ ] **Step 3: Commit dissector changes**

```bash
git add crates/fireshark-dissectors/src/ipv4.rs crates/fireshark-dissectors/src/ipv6.rs \
       crates/fireshark-dissectors/src/tcp.rs crates/fireshark-dissectors/src/udp.rs \
       crates/fireshark-dissectors/src/icmp.rs
git commit -m "feat: extract RFC fields in all dissectors (IPv4/IPv6/TCP/UDP/ICMP)"
```

---

## Chunk 3: Fix existing tests and add edge case tests

### Task 7: Fix existing dissector tests

**Files:**
- Modify: `crates/fireshark-dissectors/tests/transport.rs`

The existing tests in `transport.rs` that match on `Ipv4Layer` fields need the new fields added to their pattern matches. The key test is `non_initial_ipv4_fragments_skip_transport_decode` at line 140, which destructures `Ipv4Layer`.

- [ ] **Step 1: Update the fragment test pattern match**

In `crates/fireshark-dissectors/tests/transport.rs`, the test `non_initial_ipv4_fragments_skip_transport_decode` uses `find_map` to extract `Ipv4Layer`. This works via reference — since we only read fields, no changes needed to the match itself. The test accesses `ipv4.fragment_offset` and `ipv4.more_fragments`, which still exist.

Run: `cargo test -p fireshark-dissectors 2>&1 | tail -30`

If tests pass, no changes needed. If any test fails due to struct shape changes, fix the specific assertion.

- [ ] **Step 2: Add field assertions to existing TCP fixture test**

In `crates/fireshark-dissectors/tests/transport.rs`, update `decodes_tcp_ports` to also verify the new fields. The existing `ethernet_ipv4_tcp.bin` fixture has: seq=1, ack=0, data_offset=5, flags=SYN, window=1024.

Add after `assert_eq!(packet.transport_ports(), Some((51514, 443)));`:

```rust
    let tcp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Tcp(layer) => Some(layer),
            _ => None,
        })
        .expect("TCP layer");

    assert_eq!(tcp.seq, 1);
    assert_eq!(tcp.ack, 0);
    assert_eq!(tcp.data_offset, 5);
    assert!(tcp.flags.syn);
    assert!(!tcp.flags.ack);
    assert!(!tcp.flags.fin);
    assert!(!tcp.flags.rst);
    assert_eq!(tcp.window, 1024);
```

- [ ] **Step 3: Add field assertions to existing IPv4 fixture test**

In `crates/fireshark-dissectors/tests/transport.rs`, add a new test after `decodes_tcp_ports`:

```rust
#[test]
fn decodes_ipv4_fields() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv4(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.ttl, 64);
    assert_eq!(ipv4.identification, 1);
    assert_eq!(ipv4.dscp, 0);
    assert_eq!(ipv4.ecn, 0);
    assert!(ipv4.dont_fragment);
    assert!(!ipv4.more_fragments);
    assert_eq!(ipv4.fragment_offset, 0);
    assert_eq!(ipv4.header_checksum, 0);
}
```

- [ ] **Step 4: Add field assertions to existing UDP fixture test**

Update `decodes_udp_ports` in `transport.rs`:

```rust
    let udp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Udp(layer) => Some(layer),
            _ => None,
        })
        .expect("UDP layer");

    assert_eq!(udp.length, 8);
```

- [ ] **Step 5: Add field assertions to existing ICMP fixture test**

The existing `ethernet_ipv6_icmp.bin` has ICMPv6 type 128 (echo request). Since the spec only maps ICMPv4 types 0/3/8, this falls to `Other`. Update `decodes_icmp_layer`:

```rust
    let icmp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Icmp(layer) => Some(layer),
            _ => None,
        })
        .expect("ICMP layer");

    assert_eq!(icmp.type_, 128);
    assert_eq!(icmp.code, 0);
    // ICMPv6 type 128 maps to Other (only ICMPv4 types 0/3/8 have typed detail)
    assert!(matches!(icmp.detail, Some(IcmpDetail::Other { .. })));
```

Add `IcmpDetail` to the import line at the top of transport.rs:

```rust
use fireshark_core::{DecodeIssueKind, IcmpDetail, Layer};
```

- [ ] **Step 6: Add IPv6 field assertions**

Add a new test in `transport.rs`:

```rust
#[test]
fn decodes_ipv6_fields() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv6 = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Ipv6(layer) => Some(layer),
            _ => None,
        })
        .expect("IPv6 layer");

    assert_eq!(ipv6.traffic_class, 0);
    assert_eq!(ipv6.flow_label, 0);
    assert_eq!(ipv6.hop_limit, 64);
}
```

- [ ] **Step 7: Run all dissector tests**

Run: `cargo test -p fireshark-dissectors`
Expected: PASS for all tests

- [ ] **Step 8: Commit**

```bash
git add crates/fireshark-dissectors/tests/transport.rs
git commit -m "test: add field assertions for new dissector fields"
```

### Task 8: Create new fixtures

**Files:**
- Create: `fixtures/bytes/arp_reply.bin`
- Create: `fixtures/bytes/arp_gratuitous.bin`
- Create: `fixtures/bytes/ipv4_options.bin`
- Create: `fixtures/bytes/tcp_syn_ack.bin`
- Create: `fixtures/bytes/tcp_rst.bin`
- Create: `fixtures/bytes/tcp_data_offset_gt5.bin`
- Create: `fixtures/bytes/icmp_echo_reply.bin`
- Create: `fixtures/bytes/icmp_dest_unreachable.bin`
- Create: `fixtures/bytes/ipv4_ttl_zero.bin`
- Create: `fixtures/bytes/ipv4_fragment_first.bin`
- Create: `fixtures/bytes/tcp_syn.bin`
- Create: `fixtures/bytes/udp_length_mismatch.bin`
- Create: `fixtures/bytes/ethernet_truncated.bin`

- [ ] **Step 1: Generate all fixture files**

Create a script `fixtures/generate_hardening_fixtures.py` and run it:

```python
#!/usr/bin/env python3
"""Generate binary fixture files for dissector hardening tests."""
import struct
from pathlib import Path

DIR = Path(__file__).parent / "bytes"

def write(name, data):
    (DIR / name).write_bytes(bytes(data))
    print(f"  wrote {name} ({len(data)} bytes)")

# --- Ethernet helpers ---
ETH_DST = bytes.fromhex("001122334455")
ETH_SRC = bytes.fromhex("667788990abb")
ETH_BCAST = bytes.fromhex("ffffffffffff")

def eth(dst, src, etype):
    return dst + src + struct.pack(">H", etype)

# --- ARP reply (operation=2) ---
# dst=broadcast, src=00:11:22:33:44:55, EtherType=0x0806
# hw=1, proto=0x0800, hwlen=6, protolen=4, op=2
# sender_hw=00:11:22:33:44:55, sender_ip=192.168.1.1
# target_hw=66:77:88:99:aa:bb, target_ip=192.168.1.2
write("arp_reply.bin",
    eth(ETH_BCAST, bytes.fromhex("001122334455"), 0x0806) +
    struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) +
    bytes.fromhex("001122334455") + bytes([192, 168, 1, 1]) +
    bytes.fromhex("667788990abb") + bytes([192, 168, 1, 2]))

# --- ARP gratuitous (sender_ip == target_ip, operation=1) ---
write("arp_gratuitous.bin",
    eth(ETH_BCAST, bytes.fromhex("001122334455"), 0x0806) +
    struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) +
    bytes.fromhex("001122334455") + bytes([192, 168, 1, 1]) +
    bytes.fromhex("000000000000") + bytes([192, 168, 1, 1]))

# --- IPv4 with options (IHL=6, 4 bytes NOP padding) + TCP SYN ---
ipv4_opts = (
    bytes([0x46, 0x00]) +                       # version=4, IHL=6, TOS=0
    struct.pack(">H", 44) +                     # total_len = 24 (hdr) + 20 (tcp)
    struct.pack(">H", 0x0001) +                 # identification
    struct.pack(">H", 0x4000) +                 # flags=DF, offset=0
    bytes([64, 6]) +                            # TTL=64, protocol=TCP
    struct.pack(">H", 0) +                      # checksum (unchecked)
    bytes([192, 0, 2, 10]) +                    # source
    bytes([198, 51, 100, 20]) +                 # destination
    bytes([0x01, 0x01, 0x01, 0x00])             # options: NOP NOP NOP EOL
)
tcp_syn = (
    struct.pack(">HH", 51514, 443) +            # ports
    struct.pack(">II", 1, 0) +                  # seq, ack
    struct.pack(">H", 0x5002) +                 # data_offset=5, SYN
    struct.pack(">H", 1024) +                   # window
    struct.pack(">HH", 0, 0)                    # checksum, urgent
)
write("ipv4_options.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_opts + tcp_syn)

# --- TCP SYN+ACK ---
ipv4_base = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 40) +
    struct.pack(">H", 0x0002) +
    struct.pack(">H", 0x4000) +
    bytes([64, 6]) +
    struct.pack(">H", 0) +
    bytes([198, 51, 100, 20]) +
    bytes([192, 0, 2, 10])
)
tcp_syn_ack = (
    struct.pack(">HH", 443, 51514) +
    struct.pack(">II", 100, 2) +                 # seq=100, ack=2
    struct.pack(">H", 0x5012) +                  # data_offset=5, SYN+ACK
    struct.pack(">H", 65535) +                   # window
    struct.pack(">HH", 0, 0)
)
write("tcp_syn_ack.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_base + tcp_syn_ack)

# --- TCP RST ---
tcp_rst = (
    struct.pack(">HH", 443, 51514) +
    struct.pack(">II", 101, 2) +
    struct.pack(">H", 0x5004) +                  # data_offset=5, RST
    struct.pack(">H", 0) +
    struct.pack(">HH", 0, 0)
)
write("tcp_rst.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_base + tcp_rst)

# --- TCP with data_offset > 5 (options: 4 bytes NOP padding) ---
ipv4_opts_tcp = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 44) +                     # total_len = 20 + 24
    struct.pack(">H", 0x0003) +
    struct.pack(">H", 0x4000) +
    bytes([64, 6]) +
    struct.pack(">H", 0) +
    bytes([192, 0, 2, 10]) +
    bytes([198, 51, 100, 20])
)
tcp_with_opts = (
    struct.pack(">HH", 51514, 443) +
    struct.pack(">II", 1, 0) +
    struct.pack(">H", 0x6002) +                  # data_offset=6, SYN
    struct.pack(">H", 1024) +
    struct.pack(">HH", 0, 0) +
    bytes([0x01, 0x01, 0x01, 0x00])              # 4 bytes TCP options
)
write("tcp_data_offset_gt5.bin",
    eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_opts_tcp + tcp_with_opts)

# --- ICMP echo reply (type 0, ICMPv4) ---
ipv4_icmp = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 28) +                     # total_len = 20 + 8
    struct.pack(">H", 0x0004) +
    struct.pack(">H", 0x4000) +
    bytes([64, 1]) +                            # protocol=ICMP
    struct.pack(">H", 0) +
    bytes([192, 0, 2, 10]) +
    bytes([198, 51, 100, 20])
)
icmp_echo_reply = (
    bytes([0, 0]) +                              # type=0 (echo reply), code=0
    struct.pack(">H", 0) +                       # checksum
    struct.pack(">HH", 0x1234, 1)                # identifier, sequence
)
write("icmp_echo_reply.bin",
    eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_icmp + icmp_echo_reply)

# --- ICMP destination unreachable (type 3, code 4 = fragmentation needed) ---
icmp_dest_unreach = (
    bytes([3, 4]) +                              # type=3, code=4
    struct.pack(">H", 0) +                       # checksum
    struct.pack(">HH", 0, 1500)                  # unused(2), next_hop_mtu(2)
)
write("icmp_dest_unreachable.bin",
    eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_icmp + icmp_dest_unreach)

# --- IPv4 TTL=0 + TCP ---
ipv4_ttl0 = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 40) +
    struct.pack(">H", 0x0005) +
    struct.pack(">H", 0x4000) +
    bytes([0, 6]) +                             # TTL=0, protocol=TCP
    struct.pack(">H", 0) +
    bytes([192, 0, 2, 10]) +
    bytes([198, 51, 100, 20])
)
write("ipv4_ttl_zero.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_ttl0 + tcp_syn)

# --- IPv4 first fragment (MF=1, offset=0) + TCP ---
ipv4_frag = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 40) +
    struct.pack(">H", 0x0006) +
    struct.pack(">H", 0x2000) +                 # MF=1, offset=0
    bytes([64, 6]) +
    struct.pack(">H", 0) +
    bytes([192, 0, 2, 10]) +
    bytes([198, 51, 100, 20])
)
write("ipv4_fragment_first.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_frag + tcp_syn)

# --- TCP SYN only (distinct from existing fixture) ---
ipv4_syn = (
    bytes([0x45, 0x20]) +                       # TOS=0x20 (DSCP=8, ECN=0)
    struct.pack(">H", 40) +
    struct.pack(">H", 0x0007) +
    struct.pack(">H", 0x0000) +                 # no flags, no offset
    bytes([128, 6]) +                           # TTL=128
    struct.pack(">H", 0) +
    bytes([10, 0, 0, 1]) +
    bytes([10, 0, 0, 2])
)
tcp_syn_only = (
    struct.pack(">HH", 12345, 80) +
    struct.pack(">II", 1000, 0) +
    struct.pack(">H", 0x5002) +                  # data_offset=5, SYN
    struct.pack(">H", 8192) +
    struct.pack(">HH", 0, 0)
)
write("tcp_syn.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_syn + tcp_syn_only)

# --- UDP with length mismatch ---
ipv4_udp = (
    bytes([0x45, 0x00]) +
    struct.pack(">H", 28) +                     # total_len = 20 + 8
    struct.pack(">H", 0x0008) +
    struct.pack(">H", 0x4000) +
    bytes([64, 17]) +                           # protocol=UDP
    struct.pack(">H", 0) +
    bytes([192, 0, 2, 10]) +
    bytes([198, 51, 100, 20])
)
udp_mismatch = (
    struct.pack(">HH", 5353, 53) +              # ports
    struct.pack(">H", 100) +                    # length=100 but only 8 bytes captured
    struct.pack(">H", 0)                        # checksum
)
write("udp_length_mismatch.bin", eth(ETH_DST, ETH_SRC, 0x0800) + ipv4_udp + udp_mismatch)

# --- Ethernet truncated (< 14 bytes) ---
write("ethernet_truncated.bin", bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]))

print("Done!")
```

Run: `python3 fixtures/generate_hardening_fixtures.py`
Expected: All files created.

- [ ] **Step 2: Verify fixture files exist**

Run: `ls -la fixtures/bytes/arp_reply.bin fixtures/bytes/tcp_syn_ack.bin fixtures/bytes/icmp_echo_reply.bin`
Expected: Files present with expected sizes.

- [ ] **Step 3: Delete the generator script**

Run: `rm fixtures/generate_hardening_fixtures.py`

The script is one-shot; fixtures are committed as binary blobs.

- [ ] **Step 4: Commit fixtures**

```bash
git add fixtures/bytes/arp_reply.bin fixtures/bytes/arp_gratuitous.bin \
       fixtures/bytes/ipv4_options.bin fixtures/bytes/ipv4_ttl_zero.bin \
       fixtures/bytes/ipv4_fragment_first.bin fixtures/bytes/tcp_syn.bin \
       fixtures/bytes/tcp_syn_ack.bin fixtures/bytes/tcp_rst.bin \
       fixtures/bytes/tcp_data_offset_gt5.bin fixtures/bytes/udp_length_mismatch.bin \
       fixtures/bytes/icmp_echo_reply.bin fixtures/bytes/icmp_dest_unreachable.bin \
       fixtures/bytes/ethernet_truncated.bin
git commit -m "test: add hardening edge case fixtures"
```

### Task 9: Write edge case tests

**Files:**
- Modify: `crates/fireshark-dissectors/tests/transport.rs`
- Modify: `crates/fireshark-dissectors/tests/ethernet_arp.rs`
- Create: `crates/fireshark-dissectors/tests/edge_cases.rs`

- [ ] **Step 1: Add ARP edge case tests**

Expand `crates/fireshark-dissectors/tests/ethernet_arp.rs`:

```rust
use fireshark_core::Layer;
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_ethernet_arp_layers() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"Ethernet"));
    assert!(packet.layer_names().contains(&"ARP"));
}

#[test]
fn decodes_arp_reply() {
    let bytes = include_bytes!("../../../fixtures/bytes/arp_reply.bin");
    let packet = decode_packet(bytes).unwrap();

    let arp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Arp(layer) => Some(layer),
            _ => None,
        })
        .expect("ARP layer");

    assert_eq!(arp.operation, 2);
    assert_eq!(arp.sender_protocol_addr.to_string(), "192.168.1.1");
    assert_eq!(arp.target_protocol_addr.to_string(), "192.168.1.2");
}

#[test]
fn decodes_gratuitous_arp() {
    let bytes = include_bytes!("../../../fixtures/bytes/arp_gratuitous.bin");
    let packet = decode_packet(bytes).unwrap();

    let arp = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Arp(layer) => Some(layer),
            _ => None,
        })
        .expect("ARP layer");

    assert_eq!(arp.operation, 1);
    assert_eq!(arp.sender_protocol_addr, arp.target_protocol_addr);
}
```

- [ ] **Step 2: Create edge_cases.rs for new fixture tests and inline tests**

Create `crates/fireshark-dissectors/tests/edge_cases.rs`:

```rust
use fireshark_core::{DecodeIssueKind, IcmpDetail, Layer};
use fireshark_dissectors::{DecodeError, decode_packet};

// --- IPv4 with options ---

#[test]
fn ipv4_with_options_parses_through_to_transport() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_options.bin");
    let packet = decode_packet(bytes).unwrap();

    assert!(packet.layer_names().contains(&"IPv4"));
    assert!(packet.layer_names().contains(&"TCP"));
    assert_eq!(packet.transport_ports(), Some((51514, 443)));
}

// --- TCP flag combinations ---

#[test]
fn decodes_tcp_syn_ack_flags() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_syn_ack.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        })
        .expect("TCP layer");

    assert!(tcp.flags.syn);
    assert!(tcp.flags.ack);
    assert!(!tcp.flags.fin);
    assert!(!tcp.flags.rst);
    assert_eq!(tcp.seq, 100);
    assert_eq!(tcp.ack, 2);
    assert_eq!(tcp.window, 65535);
}

#[test]
fn decodes_tcp_rst_flag() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_rst.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        })
        .expect("TCP layer");

    assert!(tcp.flags.rst);
    assert!(!tcp.flags.syn);
    assert!(!tcp.flags.ack);
}

#[test]
fn tcp_with_options_skips_option_bytes() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_data_offset_gt5.bin");
    let packet = decode_packet(bytes).unwrap();

    let tcp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        })
        .expect("TCP layer");

    assert_eq!(tcp.data_offset, 6);
    assert!(tcp.flags.syn);
}

// --- TCP data_offset validation ---

#[test]
fn tcp_data_offset_below_5_is_malformed() {
    // Take valid TCP fixture and set data_offset to 4
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    // TCP header starts at byte 34, data_offset is upper nibble of byte 34+12=46
    bytes[46] = 0x40 | (bytes[46] & 0x0F); // data_offset=4
    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
    assert!(!packet.layer_names().contains(&"TCP"));
}

#[test]
fn tcp_data_offset_exceeding_buffer_is_truncated() {
    // Take valid TCP fixture and set data_offset to 15 (60 bytes)
    // but buffer only has 20 bytes of TCP
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[46] = 0xF0 | (bytes[46] & 0x0F); // data_offset=15
    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Truncated);
    assert!(!packet.layer_names().contains(&"TCP"));
}

// --- ICMP detail parsing ---

#[test]
fn decodes_icmp_echo_reply_detail() {
    let bytes = include_bytes!("../../../fixtures/bytes/icmp_echo_reply.bin");
    let packet = decode_packet(bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Icmp(i) => Some(i),
            _ => None,
        })
        .expect("ICMP layer");

    assert_eq!(icmp.type_, 0);
    assert_eq!(icmp.code, 0);
    assert_eq!(
        icmp.detail,
        Some(IcmpDetail::EchoReply {
            identifier: 0x1234,
            sequence: 1,
        })
    );
}

#[test]
fn decodes_icmp_dest_unreachable_detail() {
    let bytes = include_bytes!("../../../fixtures/bytes/icmp_dest_unreachable.bin");
    let packet = decode_packet(bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Icmp(i) => Some(i),
            _ => None,
        })
        .expect("ICMP layer");

    assert_eq!(icmp.type_, 3);
    assert_eq!(icmp.code, 4);
    assert_eq!(
        icmp.detail,
        Some(IcmpDetail::DestinationUnreachable {
            next_hop_mtu: 1500,
        })
    );
}

#[test]
fn icmp_with_only_4_bytes_has_no_detail() {
    // IPv6 + ICMP fixture, truncate to only 4 bytes of ICMP
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    // Set IPv6 payload_length to 4 (only ICMP type+code+checksum, no rest-of-header)
    bytes[18] = 0;
    bytes[19] = 4;
    // Truncate the actual buffer
    bytes.truncate(14 + 40 + 4); // ethernet + ipv6 + 4 bytes icmp

    let packet = decode_packet(&bytes).unwrap();

    let icmp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Icmp(i) => Some(i),
            _ => None,
        })
        .expect("ICMP layer");

    assert!(icmp.detail.is_none());
}

// --- Ethernet edge cases ---

#[test]
fn ethernet_truncated_returns_error() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_truncated.bin");
    let result = decode_packet(bytes);

    assert!(matches!(result, Err(DecodeError::Truncated { .. })));
}

#[test]
fn ethernet_unknown_ethertype_has_no_upper_layers() {
    // Use valid Ethernet header with unknown EtherType 0xFFFF
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[12] = 0xFF;
    bytes[13] = 0xFF;
    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.layer_names(), vec!["Ethernet"]);
    assert!(packet.issues().is_empty());
}

// --- ARP edge cases (inline) ---

#[test]
fn arp_truncated_payload_returns_error() {
    // Valid Ethernet header + only 10 bytes of ARP (need 28)
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin").to_vec();
    bytes.truncate(24); // 14 ethernet + 10 arp bytes
    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Truncated);
    assert!(!packet.layer_names().contains(&"ARP"));
}

#[test]
fn arp_non_ethernet_hardware_type_is_malformed() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin").to_vec();
    // Change hardware_type from 1 to 6 (IEEE 802) at bytes 14-15
    bytes[14] = 0;
    bytes[15] = 6;
    let packet = decode_packet(&bytes).unwrap();

    assert_eq!(packet.issues().len(), 1);
    assert_eq!(packet.issues()[0].kind(), &DecodeIssueKind::Malformed);
    assert!(!packet.layer_names().contains(&"ARP"));
}

// --- TCP SYN fixture with distinct IPv4 fields ---

#[test]
fn decodes_tcp_syn_with_dscp() {
    let bytes = include_bytes!("../../../fixtures/bytes/tcp_syn.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(i) => Some(i),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.dscp, 8); // TOS=0x20 → DSCP=8
    assert_eq!(ipv4.ecn, 0);
    assert_eq!(ipv4.ttl, 128);
    assert!(!ipv4.dont_fragment);

    let tcp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        })
        .expect("TCP layer");

    assert_eq!(tcp.source_port, 12345);
    assert_eq!(tcp.destination_port, 80);
    assert!(tcp.flags.syn);
    assert_eq!(tcp.window, 8192);
}

// --- UDP length mismatch ---

#[test]
fn udp_length_field_parsed_even_when_mismatched() {
    let bytes = include_bytes!("../../../fixtures/bytes/udp_length_mismatch.bin");
    let packet = decode_packet(bytes).unwrap();

    let udp = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Udp(u) => Some(u),
            _ => None,
        })
        .expect("UDP layer");

    assert_eq!(udp.length, 100); // Claims 100 but only 8 bytes captured
    assert_eq!(udp.source_port, 5353);
    assert_eq!(udp.destination_port, 53);
}

// --- IPv4 first fragment ---

#[test]
fn ipv4_first_fragment_decodes_transport() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_fragment_first.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(i) => Some(i),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.fragment_offset, 0);
    assert!(ipv4.more_fragments);
    // First fragment (offset=0) should still decode transport
    assert!(packet.layer_names().contains(&"TCP"));
}

// --- IPv4 TTL zero fixture ---

#[test]
fn ipv4_ttl_zero_fixture_parses() {
    let bytes = include_bytes!("../../../fixtures/bytes/ipv4_ttl_zero.bin");
    let packet = decode_packet(bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(i) => Some(i),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.ttl, 0);
    assert!(packet.issues().is_empty());
}

// --- IPv4 edge cases (inline) ---

#[test]
fn ipv4_ttl_zero_is_valid_parse() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin").to_vec();
    bytes[22] = 0; // TTL = 0
    let packet = decode_packet(&bytes).unwrap();

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv4(i) => Some(i),
            _ => None,
        })
        .expect("IPv4 layer");

    assert_eq!(ipv4.ttl, 0);
    assert!(packet.issues().is_empty());
}

// --- IPv6 edge cases ---

#[test]
fn ipv6_hop_limit_zero_is_valid_parse() {
    let mut bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin").to_vec();
    bytes[21] = 0; // hop_limit = 0
    let packet = decode_packet(&bytes).unwrap();

    let ipv6 = packet
        .layers()
        .iter()
        .find_map(|l| match l {
            Layer::Ipv6(i) => Some(i),
            _ => None,
        })
        .expect("IPv6 layer");

    assert_eq!(ipv6.hop_limit, 0);
}
```

- [ ] **Step 3: Run all dissector tests**

Run: `cargo test -p fireshark-dissectors`
Expected: PASS for all tests

- [ ] **Step 4: Commit**

```bash
git add crates/fireshark-dissectors/tests/ethernet_arp.rs \
       crates/fireshark-dissectors/tests/edge_cases.rs \
       crates/fireshark-dissectors/tests/transport.rs
git commit -m "test: add edge case tests for all dissectors"
```

---

## Chunk 4: MCP view updates

### Task 10: Update MCP LayerView and from_layer

**Files:**
- Modify: `crates/fireshark-mcp/src/model.rs`
- Modify: `crates/fireshark-mcp/tests/query.rs`

- [ ] **Step 1: Add TcpFlagsView struct to model.rs**

Add after the existing `LayerView` enum in `crates/fireshark-mcp/src/model.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TcpFlagsView {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}
```

- [ ] **Step 2: Add IcmpDetailView enum**

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum IcmpDetailView {
    EchoRequest { identifier: u16, sequence: u16 },
    EchoReply { identifier: u16, sequence: u16 },
    DestinationUnreachable { next_hop_mtu: u16 },
    Other { rest_of_header: u32 },
}
```

- [ ] **Step 3: Update LayerView variants**

Update the `LayerView` enum variants in `model.rs`:

```rust
    #[serde(rename = "IPv4")]
    Ipv4 {
        source: String,
        destination: String,
        protocol: u8,
        ttl: u8,
        identification: u16,
        dscp: u8,
        ecn: u8,
        dont_fragment: bool,
        fragment_offset: u16,
        more_fragments: bool,
        header_checksum: u16,
    },
    #[serde(rename = "IPv6")]
    Ipv6 {
        source: String,
        destination: String,
        next_header: u8,
        traffic_class: u8,
        flow_label: u32,
        hop_limit: u8,
    },
    #[serde(rename = "TCP")]
    Tcp {
        source_port: u16,
        destination_port: u16,
        seq: u32,
        ack: u32,
        data_offset: u8,
        flags: TcpFlagsView,
        window: u16,
    },
    #[serde(rename = "UDP")]
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
    },
    #[serde(rename = "ICMP")]
    Icmp {
        type_: u8,
        code: u8,
        detail: Option<IcmpDetailView>,
    },
```

- [ ] **Step 4: Update from_layer mapping**

Update the `LayerView::from_layer` method to map the new fields:

```rust
    pub fn from_layer(layer: &Layer) -> Self {
        match layer {
            Layer::Unknown => Self::Unknown,
            Layer::Ethernet(layer) => Self::Ethernet {
                source: format_mac(layer.source),
                destination: format_mac(layer.destination),
                ether_type: layer.ether_type,
            },
            Layer::Arp(layer) => Self::Arp {
                operation: layer.operation,
                sender_protocol_addr: layer.sender_protocol_addr.to_string(),
                target_protocol_addr: layer.target_protocol_addr.to_string(),
            },
            Layer::Ipv4(layer) => Self::Ipv4 {
                source: layer.source.to_string(),
                destination: layer.destination.to_string(),
                protocol: layer.protocol,
                ttl: layer.ttl,
                identification: layer.identification,
                dscp: layer.dscp,
                ecn: layer.ecn,
                dont_fragment: layer.dont_fragment,
                fragment_offset: layer.fragment_offset,
                more_fragments: layer.more_fragments,
                header_checksum: layer.header_checksum,
            },
            Layer::Ipv6(layer) => Self::Ipv6 {
                source: layer.source.to_string(),
                destination: layer.destination.to_string(),
                next_header: layer.next_header,
                traffic_class: layer.traffic_class,
                flow_label: layer.flow_label,
                hop_limit: layer.hop_limit,
            },
            Layer::Tcp(layer) => Self::Tcp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
                seq: layer.seq,
                ack: layer.ack,
                data_offset: layer.data_offset,
                flags: TcpFlagsView {
                    fin: layer.flags.fin,
                    syn: layer.flags.syn,
                    rst: layer.flags.rst,
                    psh: layer.flags.psh,
                    ack: layer.flags.ack,
                    urg: layer.flags.urg,
                    ece: layer.flags.ece,
                    cwr: layer.flags.cwr,
                },
                window: layer.window,
            },
            Layer::Udp(layer) => Self::Udp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
                length: layer.length,
            },
            Layer::Icmp(layer) => Self::Icmp {
                type_: layer.type_,
                code: layer.code,
                detail: layer.detail.map(|d| match d {
                    fireshark_core::IcmpDetail::EchoRequest {
                        identifier,
                        sequence,
                    } => IcmpDetailView::EchoRequest {
                        identifier,
                        sequence,
                    },
                    fireshark_core::IcmpDetail::EchoReply {
                        identifier,
                        sequence,
                    } => IcmpDetailView::EchoReply {
                        identifier,
                        sequence,
                    },
                    fireshark_core::IcmpDetail::DestinationUnreachable { next_hop_mtu } => {
                        IcmpDetailView::DestinationUnreachable { next_hop_mtu }
                    }
                    fireshark_core::IcmpDetail::Other { rest_of_header } => {
                        IcmpDetailView::Other { rest_of_header }
                    }
                }),
            },
        }
    }
```

- [ ] **Step 5: Add MCP test for TCP layer fields**

In `crates/fireshark-mcp/tests/query.rs`, add:

```rust
use fireshark_mcp::model::LayerView;

#[test]
fn get_packet_exposes_tcp_fields_in_detail_view() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let capture = AnalyzedCapture::open(&fixture).unwrap();

    let packet = get_packet(&capture, 0).unwrap();

    // The minimal.pcap fixture contains a TCP SYN: seq=1, ack=0, window=1024
    let tcp = packet
        .layers
        .iter()
        .find_map(|l| match l {
            LayerView::Tcp {
                seq,
                ack,
                flags,
                window,
                data_offset,
                ..
            } => Some((seq, ack, flags, window, data_offset)),
            _ => None,
        })
        .expect("TCP layer should be present");

    assert_eq!(*tcp.0, 1);       // seq
    assert_eq!(*tcp.1, 0);       // ack
    assert!(tcp.2.syn);          // flags.syn
    assert!(!tcp.2.ack);         // flags.ack
    assert_eq!(*tcp.3, 1024);    // window
    assert_eq!(*tcp.4, 5);       // data_offset
}
```

- [ ] **Step 6: Run MCP tests**

Run: `cargo test -p fireshark-mcp`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/fireshark-mcp/src/model.rs crates/fireshark-mcp/tests/query.rs
git commit -m "feat: expose new dissector fields in MCP LayerView"
```

---

## Chunk 5: Fuzz infrastructure

### Task 11: Add fuzz regression test

**Files:**
- Create: `crates/fireshark-cli/tests/fuzz_regression.rs`

- [ ] **Step 1: Create fuzz regression test file**

Create `crates/fireshark-cli/tests/fuzz_regression.rs`:

```rust
mod support;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

#[test]
fn fuzz_fixture_does_not_panic() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");
    let reader = CaptureReader::open(fixture).unwrap();
    for decoded in Pipeline::new(reader, decode_packet) {
        let _ = decoded; // Don't care about errors, just no panics
    }
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p fireshark-cli fuzz_fixture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/fireshark-cli/tests/fuzz_regression.rs
git commit -m "test: add fuzz fixture regression test"
```

### Task 12: Set up cargo-fuzz

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/fuzz_decode_packet.rs`
- Create: `fuzz/fuzz_targets/fuzz_capture_reader.rs`

- [ ] **Step 1: Create fuzz Cargo.toml**

Create `fuzz/Cargo.toml`:

```toml
[package]
name = "fireshark-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
fireshark-dissectors = { path = "../crates/fireshark-dissectors" }
fireshark-file = { path = "../crates/fireshark-file" }
tempfile = "3"

[[bin]]
name = "fuzz_decode_packet"
path = "fuzz_targets/fuzz_decode_packet.rs"
doc = false

[[bin]]
name = "fuzz_capture_reader"
path = "fuzz_targets/fuzz_capture_reader.rs"
doc = false

[workspace]
```

- [ ] **Step 2: Create decode_packet fuzz target**

Create `fuzz/fuzz_targets/fuzz_decode_packet.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed raw bytes as a complete Ethernet frame through the full
    // dissector chain. We only care that it doesn't panic — errors are fine.
    let _ = fireshark_dissectors::decode_packet(data);
});
```

- [ ] **Step 3: Create capture_reader fuzz target**

Create `fuzz/fuzz_targets/fuzz_capture_reader.rs`:

```rust
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

- [ ] **Step 4: Verify fuzz targets compile**

Run: `cd fuzz && cargo check 2>&1 | tail -5`
Expected: PASS (compiles but doesn't run fuzzer)

- [ ] **Step 5: Commit**

```bash
git add fuzz/
git commit -m "feat: add cargo-fuzz infrastructure with two fuzz targets"
```

---

## Chunk 6: Full verification

### Task 13: Full verification

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: PASS

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: PASS — all tests across all crates

- [ ] **Step 4: Smoke test CLI output**

Run: `cargo run -p fireshark-cli -- summary fixtures/smoke/minimal.pcap`
Expected: Output still shows the timestamp and TCP summary line.

- [ ] **Step 5: Verify fuzz target runs briefly**

Run: `cd fuzz && cargo fuzz run fuzz_decode_packet -- -max_total_time=5 2>&1 | tail -3`
Expected: Fuzzer starts and runs for 5 seconds without crashes.

- [ ] **Step 6: Run just check**

Run: `just check`
Expected: PASS

- [ ] **Step 7: Commit any fixes**

If any verification step required fixes:
```bash
git add -A
git commit -m "fix: address verification issues for hardening pass"
```
