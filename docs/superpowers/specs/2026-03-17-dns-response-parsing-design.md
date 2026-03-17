# DNS Response Parsing — Design Spec

## Purpose

Extend the DNS dissector to parse A and AAAA answer records from DNS responses. This is a partial implementation of issue #11 — the two most useful record types for security analysis and traffic correlation.

## New Types in fireshark-core

Add to `crates/fireshark-core/src/layer.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: DnsAnswerData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswerData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Other(Vec<u8>),
}
```

Export `DnsAnswer` and `DnsAnswerData` from `fireshark-core::lib`.

## DnsLayer Changes

Add one field:

```rust
pub struct DnsLayer {
    // ... existing fields ...
    pub answers: Vec<DnsAnswer>,
}
```

Empty vec for queries and for responses where parsing fails.

## Parser Changes

In `crates/fireshark-dissectors/src/dns.rs`:

After parsing the question section, if `is_response` and `answer_count > 0`, parse answer records starting at the byte offset after the question section.

### Answer record format (RFC 1035 section 4.1.3)

Each answer record:
- Name: DNS label encoding (may use compression pointers)
- Type: 2 bytes
- Class: 2 bytes
- TTL: 4 bytes
- Rdlength: 2 bytes
- Rdata: `rdlength` bytes

Minimum per-record overhead (excluding name): 10 bytes (type + class + TTL + rdlength).

### Name handling in answers

Answer names almost always use compression pointers (pointing back to the question section). The existing `parse_name` stops at pointers and returns whatever was accumulated. For answer names this typically yields an empty string (the pointer is the first byte). This is acceptable — the answer name is usually identical to the query name, and the important data is the rdata (IP address).

### Rdata parsing

- Type 1 (A): 4 bytes → `Ipv4Addr`
- Type 28 (AAAA): 16 bytes → `Ipv6Addr`
- Other types: raw `Vec<u8>` of `rdlength` bytes

### Safety

- Cap parsed answers at 100 to prevent malicious packets with answer_count=65535
- Skip records where the rdata length doesn't match expected size for A/AAAA
- If any record is truncated, stop parsing and return whatever answers were collected so far

### Updated parse_question return

`parse_question` needs to return the byte offset where it stopped, so the answer parser knows where to start. Change the return type to include the consumed byte count.

## Filter Integration

Add to `crates/fireshark-filter/src/evaluate.rs`:

- `"dns.answer"` — bare field presence check: true if `answers` is non-empty

No individual answer field filtering in v1 (would need array-typed filter values).

## CLI Detail Rendering

In `crates/fireshark-cli/src/detail.rs`, extend `render_dns`:

```
▸ DNS
    Transaction ID: 0x1234  [Response]
    Questions: 1  Answers: 1
    Query: example.com (A)
    Answer: A 93.184.216.34 (TTL 300)
```

For AAAA: `Answer: AAAA 2606:2800:220:1::248 (TTL 300)`
For Other: `Answer: Type 15 (4 bytes)`

## MCP LayerView

Add `answers` field to the `Dns` variant in `LayerView`:

```rust
Dns {
    // ... existing fields ...
    answers: Vec<DnsAnswerView>,
}
```

Where:

```rust
pub struct DnsAnswerView {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: String,  // "93.184.216.34" or "2606:2800:..." or "4 bytes"
}
```

## Fixture

`fixtures/bytes/ethernet_ipv4_udp_dns_response.bin`: DNS response for `example.com` with one A record (93.184.216.34, TTL 300).

Layout: Ethernet (14) + IPv4 (20) + UDP (8) + DNS header (12) + question (17 for example.com) + answer (~27: pointer name + type + class + TTL + rdlength + 4 bytes rdata) = ~98 bytes.

## Testing

- `decodes_dns_response_with_a_record` — fixture, verify is_response=true, answers.len()=1, data=A(93.184.216.34), ttl=300
- `dns_query_has_empty_answers` — existing query fixture, verify answers is empty
- `dns_response_with_truncated_answer_returns_partial` — truncated fixture, some answers parsed
- Filter test: `"dns.answer"` on response → true, on query → false

## Modified Files

- `crates/fireshark-core/src/layer.rs` — add DnsAnswer, DnsAnswerData, update DnsLayer
- `crates/fireshark-core/src/lib.rs` — export new types
- `crates/fireshark-dissectors/src/dns.rs` — answer parsing after question section
- `crates/fireshark-filter/src/evaluate.rs` — add dns.answer field
- `crates/fireshark-cli/src/detail.rs` — render answers in render_dns
- `crates/fireshark-mcp/src/model.rs` — DnsAnswerView, update Dns variant + from_layer

## Out of Scope

- Compression pointer following (names in answers will be empty/partial)
- CNAME, MX, NS, SOA, TXT, SRV record parsing (issue #11)
- EDNS0, DNSSEC (issue #11)
- Per-answer filtering (`dns.answer.ip == 10.0.0.1`)
