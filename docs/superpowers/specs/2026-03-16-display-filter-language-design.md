# Display Filter Language — Design Spec

## Purpose

Add a Wireshark-style display filter expression language to fireshark. Users pass `-f <expr>` to the `summary` command to filter packets by protocol, field values, addresses, and ports. This is the third of three CLI UX specs (color, detail+hex, filters).

## Crate Structure

New crate: `fireshark-filter` in `crates/fireshark-filter/`.

Four modules:

- `lexer.rs` — tokenizes filter string into tokens
- `parser.rs` — hand-written recursive descent parser: tokens to AST
- `ast.rs` — AST node types
- `evaluate.rs` — evaluates an AST against a `DecodedFrame`, returns bool

Depends only on `fireshark-core`. No external parser dependencies.

**Public API:**

```rust
pub fn parse(input: &str) -> Result<Expr, FilterError>
pub fn evaluate(expr: &Expr, decoded: &DecodedFrame) -> bool
```

## Token Types

```rust
enum Token {
    // Boolean operators
    And, Or, Not,
    // Protocol keywords
    Tcp, Udp, Arp, Icmp, Ipv4, Ipv6, Ethernet,
    // Shorthand keywords
    Port, Src, Dst, Host,
    // Comparison operators
    Eq, Neq, Gt, Lt, Gte, Lte,
    // Literals
    Integer(u64),
    IpV4Addr(Ipv4Addr),
    IpV6Addr(Ipv6Addr),
    Cidr4(Ipv4Addr, u8),
    Bool(bool),
    // Structure
    Ident(String),  // dotted field paths like "ip.src"
    LParen, RParen,
}
```

The lexer recognizes dotted identifiers as single `Ident` tokens (e.g., `tcp.flags.syn` is one token, not three).

**Lexer disambiguation:** Tokens starting with a digit are classified by structure:
- Matches `\d+\.\d+\.\d+\.\d+/\d+` → `Cidr4`
- Matches `\d+\.\d+\.\d+\.\d+` → `IpV4Addr`
- Matches `\d+` (no dots) → `Integer`
- Contains `:` with hex digits → `IpV6Addr`

Tokens starting with a letter are always `Ident` (even if they contain dots, e.g., `ip.src`). Keywords (`and`, `or`, `tcp`, etc.) are recognized from identifiers by exact match.

## AST Types

```rust
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    HasProtocol(Protocol),
    Compare(FieldPath, CmpOp, Value),
    Shorthand(ShorthandKind),
    BareField(FieldPath),  // truthy check, e.g. "tcp.flags.syn"
}

enum Protocol { Tcp, Udp, Arp, Icmp, Ipv4, Ipv6, Ethernet }

type FieldPath = String;

enum CmpOp { Eq, Neq, Gt, Lt, Gte, Lte }

enum Value {
    Integer(u64),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Cidr4(Ipv4Addr, u8),
    Bool(bool),
}

enum ShorthandKind {
    Port(u16),
    Src(AddrValue),
    Dst(AddrValue),
    Host(AddrValue),
}

enum AddrValue {
    V4(Ipv4Addr),
    V4Cidr(Ipv4Addr, u8),
    V6(Ipv6Addr),
}
```

## Grammar

Precedence (low to high): `or` then `and` then `not` then atom.

```
expr     = or_expr
or_expr  = and_expr ("or" and_expr)*
and_expr = unary ("and" unary)*
unary    = "not" unary | atom
atom     = "(" expr ")"
         | protocol
         | "port" INTEGER
         | "src" addr_value
         | "dst" addr_value
         | "host" addr_value
         | IDENT cmp_op value
         | IDENT
```

`not` binds tighter than `and`/`or`: `not tcp and udp` means `(not tcp) and udp`. This matches Wireshark behavior.

A bare `IDENT` without a comparison operator is a truthy check. For boolean fields like `tcp.flags.syn`, this is equivalent to `tcp.flags.syn == true`. For non-boolean fields, it checks presence (the field exists in the packet).

## Error Handling

The parser returns `Result<Expr, FilterError>`. `FilterError` carries a human-readable message with approximate position:

```
error: unexpected token 'and' at position 9
```

`FilterError` implements `Display` and `std::error::Error`.

## Evaluator

### Field Registry

The evaluator resolves dotted field paths to values extracted from a `DecodedFrame`. Implemented as a match statement in `evaluate.rs`.

Supported fields:

**Frame fields:**

- `frame.len` — `frame.original_len()` (integer) — matches Wireshark convention (wire length)
- `frame.cap_len` — `frame.captured_len()` (integer)

**IPv4 fields** (from `Ipv4Layer`):

- `ip.src` — source address
- `ip.dst` — destination address
- `ip.ttl` — TTL (integer)
- `ip.id` — identification (integer)
- `ip.proto` — protocol number (integer)
- `ip.dscp` — DSCP (integer)
- `ip.ecn` — ECN (integer)
- `ip.checksum` — header checksum (integer)
- `ip.flags.df` — don't fragment (boolean)
- `ip.flags.mf` — more fragments (boolean)
- `ip.frag_offset` — fragment offset (integer)

**IPv6 fields** (from `Ipv6Layer`):

- `ip.src` — also matches IPv6 source (dual-stack)
- `ip.dst` — also matches IPv6 destination (dual-stack)
- `ipv6.hlim` — hop limit (integer)
- `ipv6.flow` — flow label (integer)
- `ipv6.tc` — traffic class (integer)
- `ipv6.nxt` — next header protocol number (integer)

**TCP fields** (from `TcpLayer`):

- `tcp.srcport` — source port (integer)
- `tcp.dstport` — destination port (integer)
- `tcp.port` — matches either src or dst port
- `tcp.seq` — sequence number (integer)
- `tcp.ack` — acknowledgment number (integer, same naming as Wireshark; `tcp.flags.ack` is the flag)
- `tcp.window` — window size (integer)
- `tcp.hdr_len` — `data_offset * 4` (integer, header length in bytes)
- `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.fin`, `tcp.flags.rst`, `tcp.flags.psh`, `tcp.flags.urg`, `tcp.flags.ece`, `tcp.flags.cwr` — flag booleans

**UDP fields** (from `UdpLayer`):

- `udp.srcport` — source port (integer)
- `udp.dstport` — destination port (integer)
- `udp.port` — matches either src or dst port
- `udp.length` — header length field (integer)

**ICMP fields** (from `IcmpLayer`):

- `icmp.type` — type number (integer)
- `icmp.code` — code number (integer)

**ARP fields** (from `ArpLayer`):

- `arp.opcode` — operation (integer)
- `arp.spa` — sender protocol address (IPv4 address)
- `arp.tpa` — target protocol address (IPv4 address)

**Ethernet fields** (from `EthernetLayer`):

- `eth.type` — EtherType (integer)
- `eth.src` and `eth.dst` — not supported in v1 (no MAC address value type; noted in Out of Scope)

### Dual-stack `ip.src` / `ip.dst`

`ip.src` resolves to the IPv4 source if the packet has an IPv4 layer, or the IPv6 source if it has an IPv6 layer. This allows `src 192.168.1.2` and `src 2001:db8::1` to work with the same shorthand. When comparing an IPv4 address against a packet with an IPv6 layer (or vice versa), the comparison returns false.

### `tcp.port` / `udp.port` semantics

`tcp.port == 443` is true if either `tcp.srcport == 443` or `tcp.dstport == 443`. Same for `udp.port`. The `port 443` shorthand checks both TCP and UDP.

### Port value range

The `port` shorthand and `tcp.port`/`udp.port` fields are `u16` (0-65535). If a literal integer exceeds `u16::MAX` in a port context, the parser returns a `FilterError` (e.g., `"port value 70000 exceeds maximum 65535"`). General integer comparisons (e.g., `ip.ttl > 300`) are valid — the comparison simply returns false since TTL is a `u8`.

### CIDR matching

For comparisons like `ip.dst == 10.0.0.0/8`, compute `(addr & mask) == (network & mask)` where the mask is derived from the prefix length. Only `==` and `!=` operators are meaningful with CIDR values.

IPv6 CIDR notation is not supported in v1. IPv6 addresses can only be matched exactly.

### Missing field behavior

If a filter references a field not present in the packet (e.g., `tcp.port` on a UDP packet), the comparison returns false. No error. This matches Wireshark behavior.

### Shorthand evaluation

- `port N` — true if TCP or UDP source or destination port equals N
- `src ADDR` — true if IPv4 or IPv6 source matches (exact or CIDR)
- `dst ADDR` — true if IPv4 or IPv6 destination matches
- `host ADDR` — true if either source or destination matches

## CLI Integration

Add `-f` / `--filter` to the `summary` subcommand only. The `detail` command targets a specific packet by number — no filtering needed.

```
fireshark summary <file> [-f <filter-expression>]
```

Flow:

1. Parse `-f <expr>` via clap (optional string argument)
2. If present, call `fireshark_filter::parse(expr)` at startup
3. If parse fails, print error to stderr and exit non-zero
4. In the summary loop, call `fireshark_filter::evaluate(&ast, &decoded)` for each packet
5. Skip packets where result is false
6. Packet numbering reflects the original capture index (not the filtered index)

## New Files

- `crates/fireshark-filter/Cargo.toml`
- `crates/fireshark-filter/src/lib.rs`
- `crates/fireshark-filter/src/ast.rs`
- `crates/fireshark-filter/src/lexer.rs`
- `crates/fireshark-filter/src/parser.rs`
- `crates/fireshark-filter/src/evaluate.rs`

## Modified Files

- `Cargo.toml` (workspace members)
- `crates/fireshark-cli/Cargo.toml` (add fireshark-filter dependency)
- `crates/fireshark-cli/src/main.rs` (add `-f` flag to summary command)
- `crates/fireshark-cli/src/summary.rs` (filter loop)

## Testing

- **Lexer unit tests:** Token sequences for `"tcp and port 443"`, `"ip.ttl > 64"`, `"src 10.0.0.0/8"`, error cases (invalid tokens).
- **Parser unit tests:** AST shapes for known expressions. Precedence tests: `not tcp and udp` parses as `(not tcp) and udp`. Error cases: `"tcp and and"`, `")"`, empty string.
- **Evaluator unit tests:** Load fixture packets via `decode_packet`, evaluate expressions, assert bool results. Cover: protocol presence, field comparisons (each operator), shorthand keywords, CIDR matching, missing-field-returns-false, bare boolean fields, dual-stack ip.src.
- **CLI integration test:** `fireshark summary fuzz-fixture.pcap -f "tcp"` — verify only TCP packets appear. `fireshark summary file.pcap -f "invalid $$"` — verify non-zero exit with error message.

## Out of Scope

- String matching, regex, `contains`, `matches` (GitHub issue #10)
- Byte slice comparisons (issue #10)
- `in` operator / set membership (issue #10)
- Bitwise operators (issue #10)
- MAC address value type and `eth.src`/`eth.dst` filtering
- IPv6 CIDR notation (exact IPv6 match only in v1)
- ICMP detail sub-fields (`icmp.id`, `icmp.seq`, `icmp.mtu`)
- Filter on `detail` subcommand
- Filter persistence or presets
- Filter autocomplete
