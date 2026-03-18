# String Filter Operators — Design Spec

## Purpose

Extend the display filter language with `contains` (substring match) and `matches` (regex match) operators, plus string-typed field values. This unlocks filtering by domain names, SNI, and IP address patterns — the most-requested filter capability.

## New Operators

### `contains` — case-insensitive substring match

```
dns.qname contains "example"
tls.sni contains "google"
ip.src contains "192.168"
```

Returns true if the field's string representation contains the given substring. Case-insensitive to match Wireshark behavior.

### `matches` — regex match

```
dns.qname matches "^evil\\."
tls.sni matches "\\.(ru|cn)$"
```

Returns true if the field's string representation matches the given regex. Uses Rust's `regex` crate. The regex is compiled once at parse time and cached in the AST.

## Token Changes

In `lexer.rs`, add:

- `Token::Contains` — keyword `contains`
- `Token::Matches` — keyword `matches`
- `Token::Str(String)` — double-quoted string literal `"..."`

String lexing: when the lexer encounters `"`, scan until the closing `"`. Support `\"` escape for literal quotes and `\\` for literal backslash. No other escape sequences needed.

## AST Changes

In `ast.rs`:

Add to `CmpOp`:
```rust
Contains,
Matches,
```

Add to `Value`:
```rust
Str(String),
Regex(regex::Regex),  // compiled at parse time
```

Note: `regex::Regex` does not implement `PartialEq`, `Eq`, or `Clone` by default. Options:
- Wrap in a newtype that implements `PartialEq` by comparing patterns: `struct CompiledRegex(regex::Regex)`
- Or store the pattern string and compile lazily in the evaluator

Simpler approach: store `Value::Str(String)` for both `contains` and `matches`. The evaluator compiles the regex on first use. This avoids `Regex` in the AST and keeps the types simple. For performance, the evaluator can cache compiled regexes in a `HashMap<String, Regex>` if needed, but for v1 just compile per-evaluation (filter expressions are evaluated per-packet, but the regex pattern is constant — the compiler should optimize this).

Actually, best approach: **compile the regex in the parser** and store it alongside the pattern string. Use a wrapper type:

```rust
#[derive(Debug, Clone)]
pub struct RegexPattern {
    pub pattern: String,
    pub compiled: regex::Regex,
}

impl PartialEq for RegexPattern {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}
impl Eq for RegexPattern {}
```

Then `Value::Regex(RegexPattern)`.

## Parser Changes

In `parser.rs`, update `parse_atom`:

After parsing an `IDENT`, check if the next token is `Contains` or `Matches`:
- `IDENT contains "string"` → `Expr::Compare(field, CmpOp::Contains, Value::Str(string))`
- `IDENT matches "regex"` → `Expr::Compare(field, CmpOp::Matches, Value::Regex(compiled))`

If the regex pattern is invalid, return `FilterError` with the regex error message.

Also accept `contains` and `matches` with `Eq` operator for backward compatibility:
- `dns.qname contains "foo"` (natural syntax)

String values can also be used with `==` and `!=` for exact match:
- `dns.qname == "example.com"` (exact string equality)
- `tls.sni != "test.local"` (exact string inequality)

## Evaluator Changes

### New FieldValue variant

```rust
enum FieldValue {
    Integer(u64),
    Address(IpAddr),
    Bool(bool),
    PortPair(u16, u16),
    Str(String),  // NEW
}
```

### New string-typed fields

| Field | Source | Type |
|-------|--------|------|
| `dns.qname` | `DnsLayer.query_name` | Str (None → field absent) |
| `tls.sni` | `TlsClientHelloLayer.sni` | Str (None → field absent) |

### Existing fields with string representation

`ip.src`, `ip.dst`, `arp.spa`, `arp.tpa` already resolve as `Address` or `Integer`. For `contains`/`matches` on these fields, the evaluator converts the `FieldValue` to its string representation before applying the string operator. This means `ip.src contains "192.168"` works by converting the `IpAddr` to a string and checking the substring.

### Comparison logic for string operators

```rust
(FieldValue::Str(s), CmpOp::Contains, Value::Str(needle)) => {
    s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}
(FieldValue::Str(s), CmpOp::Matches, Value::Regex(re)) => {
    re.compiled.is_match(s)
}
(FieldValue::Str(s), CmpOp::Eq, Value::Str(v)) => s == *v
(FieldValue::Str(s), CmpOp::Neq, Value::Str(v)) => s != *v
```

For non-Str field values with `contains`/`matches`, convert to string first:
```rust
(field_value, CmpOp::Contains, Value::Str(needle)) => {
    let s = field_value_to_string(field_value);
    s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}
```

Where `field_value_to_string` converts `Integer` → decimal string, `Address` → IP string, `Bool` → "true"/"false", `PortPair` → "src,dst".

## Dependencies

Add `regex = "1"` to `crates/fireshark-filter/Cargo.toml`.

## Testing

### Lexer tests
- `"hello world"` → `Token::Str("hello world")`
- `"escaped \"quote\""` → `Token::Str("escaped \"quote\"")`
- `contains` → `Token::Contains`
- `matches` → `Token::Matches`

### Parser tests
- `dns.qname contains "example"` → `Compare("dns.qname", Contains, Str("example"))`
- `tls.sni matches "^evil"` → `Compare("tls.sni", Matches, Regex(...))`
- `dns.qname == "example.com"` → `Compare("dns.qname", Eq, Str("example.com"))`
- Invalid regex: `dns.qname matches "["` → FilterError

### Evaluator tests
- `dns.qname contains "google"` on DNS query for google.com → true
- `dns.qname contains "evil"` on DNS query for google.com → false
- `tls.sni contains "example"` on TLS ClientHello with SNI example.com → true
- `ip.src contains "192.168"` on IPv4 packet → true
- `dns.qname matches "^google"` → true
- `dns.qname matches "\\.com$"` → true
- `dns.qname == "google.com"` → true (exact match)
- Case insensitivity: `dns.qname contains "GOOGLE"` → true

### CLI integration
- `fireshark summary capture.pcap -f 'dns.qname contains "google"'` → filters DNS packets

## Modified Files

- `crates/fireshark-filter/Cargo.toml` — add regex dependency
- `crates/fireshark-filter/src/ast.rs` — `Contains`, `Matches` ops, `Str`, `Regex` values, `RegexPattern` wrapper
- `crates/fireshark-filter/src/lexer.rs` — `Token::Contains`, `Token::Matches`, `Token::Str`, string scanning
- `crates/fireshark-filter/src/parser.rs` — parse `contains`/`matches` expressions, compile regex
- `crates/fireshark-filter/src/evaluate.rs` — `FieldValue::Str`, `dns.qname`/`tls.sni` fields, string comparison logic
- `crates/fireshark-filter/src/lib.rs` — re-export if needed

## Out of Scope

- `in` operator / set membership (deferred past v1.0)
- Bitwise operators (deferred past v1.0)
- Byte slice comparisons
- Case-sensitive mode flag
- Regex flags (multiline, dotall)
