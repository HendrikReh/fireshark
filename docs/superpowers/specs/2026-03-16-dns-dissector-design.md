# DNS Dissector — Design Spec

## Purpose

Add a DNS protocol dissector to fireshark, introducing the application-layer dispatch mechanism. DNS is the first dissector that operates on TCP/UDP payload rather than transport headers, dispatched by port number (53).

## Application-Layer Dispatch Architecture

### New function: `append_application_layer`

A new function in `crates/fireshark-dissectors/src/lib.rs`, called after a transport layer is successfully decoded. It receives the transport `Layer` (for port extraction), the application payload bytes, and the absolute byte offset.

```
decode_packet
  → append_network_layer
    → parse_transport (TCP/UDP)
    → append_application_layer (NEW)
      → extract ports from Layer::Tcp or Layer::Udp
      → match on src/dst ports
      → dns::parse if either port == 53
```

### Payload computation

After transport decode, the orchestrator computes:

```rust
let transport_len = transport_span.len;
let app_payload = &payload[transport_len..];
let app_offset = payload_offset + transport_len;
```

Where `payload` is the IP payload and `transport_len` is the transport header size from the span. Application dissectors are only called if `app_payload` is non-empty.

### Known-port table

The initial port table in `append_application_layer`:

| Port | Protocol |
|------|----------|
| 53 | DNS |

Future additions: 80 (HTTP), 443 (TLS). Each gets a new match arm.

Both source and destination ports are checked — DNS responses come FROM port 53, queries go TO port 53.

**UDP only in v1:** The initial dispatch only fires for `Layer::Udp`. TCP port 53 is not dispatched because DNS-over-TCP prepends a 2-byte length prefix (RFC 1035 section 4.2.2) that the parser would misinterpret as the transaction ID, producing corrupt field values. TCP DNS support requires stripping the length prefix first and is deferred.

## DNS Layer Type

Add to `fireshark-core::layer`:

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

Add `Dns(DnsLayer)` variant to the `Layer` enum. Add `"DNS"` to `Layer::name()`. Export `DnsLayer` from `fireshark-core::lib`.

Note: `DnsLayer` contains `String` so it cannot derive `Copy`, unlike most other layer structs which are all `Copy`-able. This is acceptable — `Layer` itself is already not `Copy`.

`query_name` is `Option<String>`:

- `Some("example.com")` when the question section is parseable
- `None` when the question section is truncated, empty, or uses name compression pointers that we can't follow in v1

`query_type` is `Option<u16>`:

- `Some(1)` for A records, `Some(28)` for AAAA, etc.
- `None` when the question section couldn't be fully parsed

## DNS Dissector

New file: `crates/fireshark-dissectors/src/dns.rs`

### Constants

```rust
pub const UDP_PORT: u16 = 53;
pub const TCP_PORT: u16 = 53;
const HEADER_LEN: usize = 12;
```

### Parse function

```rust
pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError>
```

**Fixed header** (12 bytes):

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 2 | transaction_id |
| 2 | 2 | flags: `is_response = flags & 0x8000 != 0`, `opcode = (flags >> 11) & 0x0F` |
| 4 | 2 | question_count |
| 6 | 2 | answer_count |
| 8 | 2 | authority_count (read but not stored) |
| 10 | 2 | additional_count (read but not stored) |

Returns `DecodeError::Truncated` if `bytes.len() < 12`.

**Question section parsing:**

After the 12-byte header, attempt to parse the first question entry:

1. Parse the query name using DNS label encoding (see below)
2. If name parsing succeeds and there are 4+ bytes remaining after the name, read query_type (2 bytes) and query_class (2 bytes, read but not stored)
3. If any step fails (truncated, pointer encountered), set `query_name` and `query_type` to `None`

No `DecodeError::Malformed` for unparseable question sections — DNS is tolerant. Set optional fields to `None` and return the layer with whatever was parsed from the fixed header.

### DNS name parsing

Walk length-prefixed labels starting at a given offset in the DNS message:

1. Read byte N at current position
2. If N == 0: end of name, return accumulated labels joined by `.`
3. If N has top two bits set (N & 0xC0 == 0xC0): compression pointer, stop parsing, return whatever was accumulated so far (may be empty string → convert to `None`)
4. If N > 63: invalid label length, stop parsing, return `None`
5. Otherwise: read N bytes as a label, append to accumulated labels, advance position by N+1
6. Repeat from step 1

Safety limits:

- Max total name length: 255 bytes (per RFC 1035)
- Max label count: 128 (prevent malicious deeply nested names)
- All slice accesses bounds-checked against `bytes.len()`

The name parser is a private function within `dns.rs`:

```rust
fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)>
```

Returns `Some((name, bytes_consumed))` on success, `None` on failure. The `bytes_consumed` value is used to advance past the name to read query_type.

## DNS Span

The DNS span covers the entire application payload: `LayerSpan { offset: app_offset, len: app_payload.len() }`. DNS consumes all remaining bytes — there is no layer after DNS.

## Filter Integration

### Protocol keyword

Add `Dns` to the `Protocol` enum in `fireshark-filter::ast`. Add `"dns"` to the lexer keyword table. Add `Layer::Dns(_)` to the protocol-presence check in `evaluate.rs`.

### Filter fields

| Field | Source | Type |
|-------|--------|------|
| `dns.id` | `DnsLayer.transaction_id` | Integer |
| `dns.qr` | `DnsLayer.is_response` | Bool |
| `dns.opcode` | `DnsLayer.opcode` | Integer |
| `dns.qcount` | `DnsLayer.question_count` | Integer |
| `dns.acount` | `DnsLayer.answer_count` | Integer |
| `dns.qtype` | `DnsLayer.query_type` | Integer (None → field absent) |

**Option field behavior:** When `query_type` is `None`, `resolve_layer_field` returns `None` and any comparison (e.g., `dns.qtype == 1`) evaluates to `false`. Bare field usage (`dns.qtype` alone) also returns `false` since the field is absent.

**`dns.qr` bare-field semantics:** `dns.qr` as a bare field returns the boolean value of `is_response`. This means `dns.qr` alone matches only DNS *responses*. To match queries, use `not dns.qr` or `dns.qr == false`.

`dns.qname` is not filterable in v1 since the filter language has no string comparison operators (deferred to issue #10). The field exists on the layer but is not in the filter registry.

## CLI Updates

### Color map

Add `"DNS"` → `Color::Magenta` in `crates/fireshark-cli/src/color.rs`.

### Detail rendering

Add `render_dns` in `crates/fireshark-cli/src/detail.rs`:

```
▸ DNS
    Transaction ID: 0x1234  [Query]
    Questions: 1  Answers: 0
    Query: example.com (A)
```

- `[Query]` or `[Response]` based on `is_response`
- Query type shown as name if known (A, AAAA, MX, CNAME, NS, PTR, SOA, TXT) or numeric
- If `query_name` is `None`: show `Query: <unparseable>`

## MCP Updates

Add `Dns` variant to `LayerView` in `crates/fireshark-mcp/src/model.rs`:

```rust
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
```

Update `LayerView::from_layer` to map `Layer::Dns`.

## Fixture

`fixtures/bytes/ethernet_ipv4_udp_dns.bin`: handcrafted binary blob containing:

- Ethernet header (14 bytes): standard MACs, EtherType 0x0800
- IPv4 header (20 bytes): protocol 17 (UDP), total_len covering full packet
- UDP header (8 bytes): src port 12345, dst port 53, length covering DNS payload
- DNS query (variable): transaction_id=0x1234, QR=0 (query), opcode=0 (standard), QDCOUNT=1, ANCOUNT=0, one question for `example.com` type A (1) class IN (1)

DNS question section for `example.com`: `07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01` (7"example" 3"com" 0 type=1 class=1)

Total fixture: 71 bytes (14 + 20 + 8 + 12 + 17).

## Testing

**`crates/fireshark-dissectors/tests/dns.rs`:**

- `decodes_dns_query` — fixture produces DnsLayer with transaction_id=0x1234, is_response=false, query_name=Some("example.com"), query_type=Some(1)
- `decodes_dns_layer_names` — packet has layers Ethernet, IPv4, UDP, DNS
- `dns_truncated_header` — fixture truncated to Ethernet+IPv4+UDP+6 bytes, produces truncation issue, no DNS layer
- `dns_with_compression_pointer_yields_none_name` — inline fixture with 0xC0 pointer in name, query_name is None
- `dns_span_covers_full_payload` — span offset/len matches the DNS portion of the frame

**`crates/fireshark-dissectors/tests/transport.rs`:**

- `decode_packet_produces_dns_spans` — verify 4-layer span (Ethernet + IPv4 + UDP + DNS)

**CLI integration:**

- `fireshark summary fuzz-fixture.pcap -f "dns"` — filters to DNS packets only (port 53 traffic exists in the fuzz fixture)

## New Files

- `crates/fireshark-dissectors/src/dns.rs`
- `crates/fireshark-dissectors/tests/dns.rs`
- `fixtures/bytes/ethernet_ipv4_udp_dns.bin`

## Modified Files

- `crates/fireshark-core/src/layer.rs` — add DnsLayer struct + Layer::Dns variant
- `crates/fireshark-core/src/lib.rs` — export DnsLayer
- `crates/fireshark-dissectors/src/lib.rs` — add mod dns, add append_application_layer, wire dispatch
- `crates/fireshark-filter/src/ast.rs` — add Dns to Protocol enum
- `crates/fireshark-filter/src/lexer.rs` — add "dns" keyword
- `crates/fireshark-filter/src/parser.rs` — handle Dns token as protocol
- `crates/fireshark-filter/src/evaluate.rs` — three changes: (a) add `Protocol::Dns` arm to `has_protocol`, (b) add `dns.*` fields to `resolve_layer_field`, (c) handle `Option::None` for `dns.qtype` by returning `None` from resolve
- `crates/fireshark-dissectors/tests/transport.rs` — add `decode_packet_produces_dns_spans` test
- `crates/fireshark-cli/src/color.rs` — add DNS → Magenta
- `crates/fireshark-cli/src/detail.rs` — add `render_dns` function + `Layer::Dns` arm in `render_layer` match
- `crates/fireshark-mcp/src/model.rs` — add Dns variant to LayerView + from_layer

## Out of Scope

- Answer record parsing, authority/additional sections (GitHub issue #11)
- DNS name compression pointer following (issue #11)
- EDNS0, DNSSEC (issue #11)
- DNS over TCP (2-byte length prefix would corrupt parsing; dispatch restricted to UDP only)
- DNS over HTTPS/TLS
- `dns.qname` string filtering (requires string operators, issue #10)
