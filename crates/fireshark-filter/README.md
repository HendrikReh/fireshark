# fireshark-filter

Wireshark-style display filter language for the fireshark packet analyzer.

## Overview

Parses and evaluates filter expressions against decoded packets. Hand-written lexer and recursive descent parser. Supports string operators (`contains`, `matches`) via the `regex` crate.

## Usage

```rust
use fireshark_filter::{parse, evaluate};

let expr = parse("tcp and port 443")?;
let matches = evaluate(&expr, &decoded_frame);
```

## Expression Language

### Protocol presence

```
tcp
udp
arp
dns
tls
not icmp
```

### Field comparisons

```
ip.ttl > 64
tcp.port == 443
ip.dst == 10.0.0.0/8
tcp.flags.syn == true
dns.id == 0x1234
dns.qcount > 0
```

### String operators

```
dns.qname contains "evil"         # case-insensitive substring match
tls.sni contains "example.com"    # works on any string-typed field
dns.qname matches ".*\.evil\.com" # regex match
tls.sni matches "^cdn\d+"         # regex match
ip.src contains "192.168"         # works on any field via string conversion
```

`contains` performs a case-insensitive substring search. `matches` evaluates a regular expression (powered by the `regex` crate). Both operators work on any field type -- non-string fields are converted to their string representation before matching.

### Shorthands

```
port 443          # TCP or UDP, either direction
src 192.168.1.2   # source address
dst 10.0.0.0/8    # destination with CIDR
host 192.168.1.1  # source or destination
```

### Boolean operators

```
tcp and port 443
tcp or udp
not arp
(tcp or udp) and port 53
```

## Supported Fields

| Category | Fields |
|----------|--------|
| Frame | `frame.len`, `frame.cap_len` |
| IPv4 | `ip.src`, `ip.dst`, `ip.ttl`, `ip.id`, `ip.proto`, `ip.dscp`, `ip.ecn`, `ip.checksum`, `ip.flags.df`, `ip.flags.mf`, `ip.frag_offset` |
| IPv6 | `ip.src`, `ip.dst` (dual-stack), `ipv6.hlim`, `ipv6.flow`, `ipv6.tc`, `ipv6.nxt` |
| TCP | `tcp.srcport`, `tcp.dstport`, `tcp.port`, `tcp.seq`, `tcp.ack`, `tcp.window`, `tcp.hdr_len`, `tcp.flags.{syn,ack,fin,rst,psh,urg,ece,cwr}`, `tcp.stream` |
| UDP | `udp.srcport`, `udp.dstport`, `udp.port`, `udp.length`, `udp.stream` |
| ICMP | `icmp.type`, `icmp.code` |
| ARP | `arp.opcode`, `arp.spa`, `arp.tpa` |
| DNS | `dns.id`, `dns.qr`, `dns.opcode`, `dns.qcount`, `dns.acount`, `dns.qtype`, `dns.qname` (string) |
| TLS | `tls.handshake.type`, `tls.record_version`, `tls.client_version`, `tls.selected_version`, `tls.cipher_suite`, `tls.sni` (string) |
| Ethernet | `eth.type` |

## Architecture

```
input string -> lexer -> tokens -> parser -> AST -> evaluator(packet) -> bool
```

- `ast.rs` — expression tree types
- `lexer.rs` — tokenizer with IPv4/IPv6/CIDR disambiguation
- `parser.rs` — recursive descent with correct operator precedence
- `evaluate.rs` — field resolution and comparison logic

---

**Version:** 0.8.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
