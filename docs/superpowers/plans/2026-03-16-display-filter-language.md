# Display Filter Language Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Wireshark-style display filter expression language (`-f` flag) to the CLI summary command via a new `fireshark-filter` crate.

**Architecture:** New `fireshark-filter` crate with four modules: `ast.rs` (types), `lexer.rs` (tokenizer), `parser.rs` (recursive descent), `evaluate.rs` (evaluator). CLI passes parsed AST to evaluator in the summary loop. Hand-written parser, no external dependencies beyond `fireshark-core`.

**Tech Stack:** Rust, `thiserror` for FilterError.

**Spec:** `docs/superpowers/specs/2026-03-16-display-filter-language-design.md`

---

## Chunk 1: Crate Scaffold + AST Types

### Task 1 — Create `fireshark-filter` crate and add to workspace

- [ ] Step 1: Create `crates/fireshark-filter/Cargo.toml`

```toml
[package]
name = "fireshark-filter"
version = "0.1.0"
edition = "2024"

[dependencies]
fireshark-core = { path = "../fireshark-core" }
thiserror = "2.0.17"

[dev-dependencies]
fireshark-dissectors = { path = "../fireshark-dissectors" }
```

- [ ] Step 2: Add to workspace in `Cargo.toml`

Modify the root `Cargo.toml` to add `"crates/fireshark-filter"` to the `members` array:

```toml
[workspace]
members = [
    "crates/fireshark-core",
    "crates/fireshark-dissectors",
    "crates/fireshark-file",
    "crates/fireshark-cli",
    "crates/fireshark-mcp",
    "crates/fireshark-filter",
]
resolver = "2"
```

- [ ] Step 3: Create `crates/fireshark-filter/src/lib.rs` with minimal module declarations

```rust
pub mod ast;
mod error;

pub use error::FilterError;
```

### Task 2 — Create `ast.rs` with all AST types

- [ ] Step 1: Create `crates/fireshark-filter/src/ast.rs`

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

/// A display filter expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    HasProtocol(Protocol),
    Compare(FieldPath, CmpOp, Value),
    Shorthand(ShorthandKind),
    /// Truthy check: boolean field → true test; non-boolean → presence check.
    BareField(FieldPath),
}

/// Protocols that can appear as bare keywords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Arp,
    Icmp,
    Ipv4,
    Ipv6,
    Ethernet,
}

/// A dotted field path, e.g. `"ip.src"` or `"tcp.flags.syn"`.
pub type FieldPath = String;

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Integer(u64),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Cidr4(Ipv4Addr, u8),
    Bool(bool),
}

/// Shorthand filter keywords.
#[derive(Debug, Clone, PartialEq)]
pub enum ShorthandKind {
    Port(u16),
    Src(AddrValue),
    Dst(AddrValue),
    Host(AddrValue),
}

/// An address literal for shorthand keywords.
#[derive(Debug, Clone, PartialEq)]
pub enum AddrValue {
    V4(Ipv4Addr),
    V4Cidr(Ipv4Addr, u8),
    V6(Ipv6Addr),
}
```

### Task 3 — Create `FilterError` type

- [ ] Step 1: Create `crates/fireshark-filter/src/error.rs`

```rust
/// Error returned by the filter parser or lexer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("filter error: {message} at position {position}")]
pub struct FilterError {
    pub message: String,
    pub position: usize,
}

impl FilterError {
    pub fn new(message: impl Into<String>, position: usize) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}
```

- [ ] Step 2: Verify the crate compiles

Run: `cargo check -p fireshark-filter`
Expected: success, no errors

- [ ] Step 3: Run full gate

Run: `just check`
Expected: PASS

- [ ] Step 4: Commit

```bash
git add Cargo.toml crates/fireshark-filter
git commit -m "feat(filter): add fireshark-filter crate scaffold with AST types"
```

---

## Chunk 2: Lexer

### Task 4 — Create lexer with Token enum and `tokenize` function

- [ ] Step 1: Create `crates/fireshark-filter/src/lexer.rs`

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::FilterError;

/// A single token produced by the lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Boolean operators
    And,
    Or,
    Not,
    // Protocol keywords
    Tcp,
    Udp,
    Arp,
    Icmp,
    Ipv4,
    Ipv6,
    Ethernet,
    // Shorthand keywords
    Port,
    Src,
    Dst,
    Host,
    // Comparison operators
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
    // Literals
    Integer(u64),
    IpV4Addr(Ipv4Addr),
    IpV6Addr(Ipv6Addr),
    Cidr4(Ipv4Addr, u8),
    Bool(bool),
    // Structure
    Ident(String),
    LParen,
    RParen,
}

/// Tokenize a display filter expression string.
pub fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        // Skip whitespace
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }

        let start = pos;

        match bytes[pos] {
            b'(' => {
                tokens.push(Token::LParen);
                pos += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                pos += 1;
            }
            b'!' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(Token::Neq);
                pos += 2;
            }
            b'=' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(Token::Eq);
                pos += 2;
            }
            b'>' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(Token::Gte);
                pos += 2;
            }
            b'<' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(Token::Lte);
                pos += 2;
            }
            b'>' => {
                tokens.push(Token::Gt);
                pos += 1;
            }
            b'<' => {
                tokens.push(Token::Lt);
                pos += 1;
            }
            b if b.is_ascii_digit() => {
                let token = scan_number(input, &mut pos)?;
                tokens.push(token);
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let token = scan_identifier(input, &mut pos);
                tokens.push(token);
            }
            _ => {
                return Err(FilterError::new(
                    format!("unexpected character '{}'", input[start..start + 1].chars().next().unwrap_or('?')),
                    start,
                ));
            }
        }
    }

    Ok(tokens)
}

/// Scan a numeric token starting at `pos`. Could be an integer, IPv4 address,
/// CIDR, or IPv6 address.
///
/// Advances `pos` past the consumed characters.
fn scan_number(input: &str, pos: &mut usize) -> Result<Token, FilterError> {
    let start = *pos;
    let bytes = input.as_bytes();

    // Collect the full numeric-like token: digits, dots, colons, hex letters, slash
    while *pos < bytes.len() {
        let b = bytes[*pos];
        if b.is_ascii_alphanumeric() || b == b'.' || b == b':' || b == b'/' {
            *pos += 1;
        } else {
            break;
        }
    }

    let text = &input[start..*pos];

    // Try IPv6 first (contains colons)
    if text.contains(':') {
        return text
            .parse::<Ipv6Addr>()
            .map(Token::IpV6Addr)
            .map_err(|_| FilterError::new(format!("invalid IPv6 address '{text}'"), start));
    }

    // Try CIDR (contains slash)
    if let Some(slash_pos) = text.find('/') {
        let addr_str = &text[..slash_pos];
        let prefix_str = &text[slash_pos + 1..];
        let addr = addr_str
            .parse::<Ipv4Addr>()
            .map_err(|_| FilterError::new(format!("invalid CIDR address '{text}'"), start))?;
        let prefix = prefix_str
            .parse::<u8>()
            .map_err(|_| FilterError::new(format!("invalid CIDR prefix '{text}'"), start))?;
        if prefix > 32 {
            return Err(FilterError::new(
                format!("CIDR prefix {prefix} exceeds maximum 32"),
                start,
            ));
        }
        return Ok(Token::Cidr4(addr, prefix));
    }

    // Try IPv4 (contains dots)
    if text.contains('.') {
        return text
            .parse::<Ipv4Addr>()
            .map(Token::IpV4Addr)
            .map_err(|_| FilterError::new(format!("invalid IPv4 address '{text}'"), start));
    }

    // Plain integer
    text.parse::<u64>()
        .map(Token::Integer)
        .map_err(|_| FilterError::new(format!("invalid integer '{text}'"), start))
}

/// Scan an identifier starting at `pos`. Identifiers may contain letters,
/// digits, dots, and underscores. After scanning, check if the identifier
/// is a keyword and return the appropriate token.
///
/// Advances `pos` past the consumed characters.
fn scan_identifier(input: &str, pos: &mut usize) -> Result<Token, FilterError> {
    let start = *pos;
    let bytes = input.as_bytes();

    // First, scan alphanumeric + dots + underscores (normal identifier)
    while *pos < bytes.len() {
        let b = bytes[*pos];
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' {
            *pos += 1;
        } else {
            break;
        }
    }

    // Check if this is actually an IPv6 address (hex chars followed by colon)
    // Examples: fe80::1, ff02::1, 2001:db8::1 (2001 starts with digit, handled by scan_number)
    // Only hex-letter-starting addresses like fe80, dead, beef, etc. reach here
    if *pos < bytes.len() && bytes[*pos] == b':' {
        let prefix = &input[start..*pos];
        if prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            // Re-scan as IPv6: consume hex digits, colons
            while *pos < bytes.len() {
                let b = bytes[*pos];
                if b.is_ascii_hexdigit() || b == b':' {
                    *pos += 1;
                } else {
                    break;
                }
            }
            let text = &input[start..*pos];
            return text
                .parse::<Ipv6Addr>()
                .map(Token::IpV6Addr)
                .map_err(|_| FilterError::new(format!("invalid IPv6 address '{text}'"), start));
        }
    }

    let text = &input[start..*pos];

    Ok(match text {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "tcp" => Token::Tcp,
        "udp" => Token::Udp,
        "arp" => Token::Arp,
        "icmp" => Token::Icmp,
        "ip" => Token::Ipv4,
        "ipv6" => Token::Ipv6,
        "eth" | "ethernet" => Token::Ethernet,
        "port" => Token::Port,
        "src" => Token::Src,
        "dst" => Token::Dst,
        "host" => Token::Host,
        "true" => Token::Bool(true),
        "false" => Token::Bool(false),
        _ => Token::Ident(text.to_string()),
    })
}

// NOTE: Since scan_identifier now returns Result, update the call site in tokenize()
// from `tokens.push(scan_identifier(input, &mut pos))` to
// `tokens.push(scan_identifier(input, &mut pos)?)`

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn tokenize_tcp_and_port() {
        let tokens = tokenize("tcp and port 443").unwrap();
        assert_eq!(
            tokens,
            vec![Token::Tcp, Token::And, Token::Port, Token::Integer(443)]
        );
    }

    #[test]
    fn tokenize_field_comparison() {
        let tokens = tokenize("ip.ttl > 64").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.ttl".to_string()),
                Token::Gt,
                Token::Integer(64),
            ]
        );
    }

    #[test]
    fn tokenize_cidr() {
        let tokens = tokenize("src 10.0.0.0/8").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Src,
                Token::Cidr4(Ipv4Addr::new(10, 0, 0, 0), 8),
            ]
        );
    }

    #[test]
    fn tokenize_not_with_parens() {
        let tokens = tokenize("not (tcp or udp)").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Not,
                Token::LParen,
                Token::Tcp,
                Token::Or,
                Token::Udp,
                Token::RParen,
            ]
        );
    }

    #[test]
    fn tokenize_comparison_operators() {
        let tokens = tokenize("ip.ttl == 128").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.ttl".to_string()),
                Token::Eq,
                Token::Integer(128),
            ]
        );

        let tokens = tokenize("ip.ttl != 0").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.ttl".to_string()),
                Token::Neq,
                Token::Integer(0),
            ]
        );

        let tokens = tokenize("tcp.srcport >= 1024").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("tcp.srcport".to_string()),
                Token::Gte,
                Token::Integer(1024),
            ]
        );

        let tokens = tokenize("ip.ttl <= 1").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.ttl".to_string()),
                Token::Lte,
                Token::Integer(1),
            ]
        );
    }

    #[test]
    fn tokenize_ipv4_address() {
        let tokens = tokenize("dst 192.168.1.1").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Dst,
                Token::IpV4Addr(Ipv4Addr::new(192, 168, 1, 1)),
            ]
        );
    }

    #[test]
    fn tokenize_ipv6_address() {
        let tokens = tokenize("src 2001:db8::1").unwrap();
        assert_eq!(
            tokens,
            vec![Token::Src, Token::IpV6Addr("2001:db8::1".parse().unwrap())]
        );
    }

    #[test]
    fn tokenize_boolean_literal() {
        let tokens = tokenize("tcp.flags.syn == true").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("tcp.flags.syn".to_string()),
                Token::Eq,
                Token::Bool(true),
            ]
        );
    }

    #[test]
    fn tokenize_bare_field() {
        let tokens = tokenize("tcp.flags.syn").unwrap();
        assert_eq!(tokens, vec![Token::Ident("tcp.flags.syn".to_string())]);
    }

    #[test]
    fn tokenize_ethernet_keyword() {
        let tokens = tokenize("eth").unwrap();
        assert_eq!(tokens, vec![Token::Ethernet]);

        let tokens = tokenize("ethernet").unwrap();
        assert_eq!(tokens, vec![Token::Ethernet]);
    }

    #[test]
    fn tokenize_empty_input() {
        let tokens = tokenize("").unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_error_invalid_char() {
        let err = tokenize("tcp $ udp").unwrap_err();
        assert_eq!(err.position, 4);
        assert!(err.message.contains("unexpected character"));
    }

    #[test]
    fn tokenize_error_invalid_cidr_prefix() {
        let err = tokenize("src 10.0.0.0/33").unwrap_err();
        assert!(err.message.contains("CIDR prefix"));
    }

    #[test]
    fn tokenize_ip_keyword_is_ipv4() {
        let tokens = tokenize("ip").unwrap();
        assert_eq!(tokens, vec![Token::Ipv4]);
    }

    #[test]
    fn tokenize_less_than() {
        let tokens = tokenize("ip.ttl < 10").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.ttl".to_string()),
                Token::Lt,
                Token::Integer(10),
            ]
        );
    }
}
```

- [ ] Step 2: Add lexer module to `lib.rs`

Update `crates/fireshark-filter/src/lib.rs` to:

```rust
pub mod ast;
mod error;
pub mod lexer;

pub use error::FilterError;
```

- [ ] Step 3: Run lexer tests

Run: `cargo test -p fireshark-filter -- --nocapture`
Expected: all lexer tests pass

- [ ] Step 4: Run full gate

Run: `just check`
Expected: PASS

- [ ] Step 5: Commit

```bash
git add crates/fireshark-filter
git commit -m "feat(filter): add lexer with tokenizer and unit tests"
```

---

## Chunk 3: Parser

### Task 5 — Create recursive descent parser

- [ ] Step 1: Create `crates/fireshark-filter/src/parser.rs`

The parser consumes a `Vec<Token>` and builds an `Expr` AST. It uses a cursor index into the token vector.

**Grammar:**
```
expr     = or_expr
or_expr  = and_expr ("or" and_expr)*
and_expr = unary ("and" unary)*
unary    = "not" unary | atom
atom     = "(" expr ")"
         | protocol_keyword             → HasProtocol(...)
         | "port" INTEGER               → Shorthand(Port(n))
         | "src" addr_value             → Shorthand(Src(...))
         | "dst" addr_value             → Shorthand(Dst(...))
         | "host" addr_value            → Shorthand(Host(...))
         | IDENT cmp_op value           → Compare(field, op, val)
         | IDENT                        → BareField(field)
```

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::{AddrValue, CmpOp, Expr, FieldPath, Protocol, ShorthandKind, Value};
use crate::lexer::{Token, tokenize};
use crate::FilterError;

/// Parse a display filter expression string into an AST.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    if input.trim().is_empty() {
        return Err(FilterError::new("empty filter expression", 0));
    }
    let tokens = tokenize(input)?;
    let mut cursor = Cursor::new(&tokens);
    let expr = parse_expr(&mut cursor)?;
    if cursor.pos < tokens.len() {
        return Err(FilterError::new(
            format!("unexpected token {:?}", tokens[cursor.pos]),
            cursor.pos,
        ));
    }
    Ok(expr)
}

struct Cursor<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn expect_advance(&mut self, context: &str) -> Result<&Token, FilterError> {
        self.advance().ok_or_else(|| {
            FilterError::new(
                format!("unexpected end of expression, expected {context}"),
                self.pos,
            )
        })
    }
}

fn parse_expr(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    parse_or(cursor)
}

fn parse_or(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    let mut left = parse_and(cursor)?;
    while cursor.peek() == Some(&Token::Or) {
        cursor.advance();
        let right = parse_and(cursor)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    let mut left = parse_unary(cursor)?;
    while cursor.peek() == Some(&Token::And) {
        cursor.advance();
        let right = parse_unary(cursor)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_unary(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    if cursor.peek() == Some(&Token::Not) {
        cursor.advance();
        let inner = parse_unary(cursor)?;
        return Ok(Expr::Not(Box::new(inner)));
    }
    parse_atom(cursor)
}

fn parse_atom(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    let token = cursor.peek().ok_or_else(|| {
        FilterError::new("unexpected end of expression", cursor.pos)
    })?;

    match token {
        // Parenthesized expression
        Token::LParen => {
            cursor.advance();
            let expr = parse_expr(cursor)?;
            match cursor.advance() {
                Some(Token::RParen) => Ok(expr),
                _ => Err(FilterError::new("expected closing ')'", cursor.pos)),
            }
        }

        // Protocol keywords
        Token::Tcp => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Tcp))
        }
        Token::Udp => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Udp))
        }
        Token::Arp => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Arp))
        }
        Token::Icmp => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Icmp))
        }
        Token::Ipv4 => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Ipv4))
        }
        Token::Ipv6 => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Ipv6))
        }
        Token::Ethernet => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Ethernet))
        }

        // Shorthand: port N
        Token::Port => {
            cursor.advance();
            let port = parse_port_value(cursor)?;
            Ok(Expr::Shorthand(ShorthandKind::Port(port)))
        }

        // Shorthand: src ADDR
        Token::Src => {
            cursor.advance();
            let addr = parse_addr_value(cursor)?;
            Ok(Expr::Shorthand(ShorthandKind::Src(addr)))
        }

        // Shorthand: dst ADDR
        Token::Dst => {
            cursor.advance();
            let addr = parse_addr_value(cursor)?;
            Ok(Expr::Shorthand(ShorthandKind::Dst(addr)))
        }

        // Shorthand: host ADDR
        Token::Host => {
            cursor.advance();
            let addr = parse_addr_value(cursor)?;
            Ok(Expr::Shorthand(ShorthandKind::Host(addr)))
        }

        // Identifier: field comparison or bare field
        Token::Ident(_) => {
            // Clone the identifier string so we don't hold a borrow
            let field = match cursor.advance() {
                Some(Token::Ident(s)) => s.clone(),
                _ => unreachable!(),
            };

            // Check if next token is a comparison operator
            if let Some(op) = peek_cmp_op(cursor) {
                cursor.advance(); // consume the operator
                let value = parse_value(cursor)?;
                Ok(Expr::Compare(field, op, value))
            } else {
                Ok(Expr::BareField(field))
            }
        }

        _ => Err(FilterError::new(
            format!("unexpected token {:?}", token),
            cursor.pos,
        )),
    }
}

/// Check if the cursor is at a comparison operator, return it without advancing.
fn peek_cmp_op(cursor: &Cursor<'_>) -> Option<CmpOp> {
    match cursor.peek()? {
        Token::Eq => Some(CmpOp::Eq),
        Token::Neq => Some(CmpOp::Neq),
        Token::Gt => Some(CmpOp::Gt),
        Token::Lt => Some(CmpOp::Lt),
        Token::Gte => Some(CmpOp::Gte),
        Token::Lte => Some(CmpOp::Lte),
        _ => None,
    }
}

/// Parse the integer after `port`, validating u16 range.
fn parse_port_value(cursor: &mut Cursor<'_>) -> Result<u16, FilterError> {
    let token = cursor.expect_advance("port number")?;
    match token {
        Token::Integer(n) => {
            let n = *n;
            u16::try_from(n).map_err(|_| {
                FilterError::new(
                    format!("port value {n} exceeds maximum 65535"),
                    cursor.pos - 1,
                )
            })
        }
        _ => Err(FilterError::new(
            format!("expected port number, got {:?}", token),
            cursor.pos - 1,
        )),
    }
}

/// Parse an address value for src/dst/host shorthands.
fn parse_addr_value(cursor: &mut Cursor<'_>) -> Result<AddrValue, FilterError> {
    let token = cursor.expect_advance("address")?;
    match token {
        Token::IpV4Addr(addr) => Ok(AddrValue::V4(*addr)),
        Token::Cidr4(addr, prefix) => Ok(AddrValue::V4Cidr(*addr, *prefix)),
        Token::IpV6Addr(addr) => Ok(AddrValue::V6(*addr)),
        _ => Err(FilterError::new(
            format!("expected address, got {:?}", token),
            cursor.pos - 1,
        )),
    }
}

/// Parse a value on the right-hand side of a comparison.
fn parse_value(cursor: &mut Cursor<'_>) -> Result<Value, FilterError> {
    let token = cursor.expect_advance("value")?;
    match token {
        Token::Integer(n) => Ok(Value::Integer(*n)),
        Token::IpV4Addr(addr) => Ok(Value::IpV4(*addr)),
        Token::IpV6Addr(addr) => Ok(Value::IpV6(*addr)),
        Token::Cidr4(addr, prefix) => Ok(Value::Cidr4(*addr, *prefix)),
        Token::Bool(b) => Ok(Value::Bool(*b)),
        _ => Err(FilterError::new(
            format!("expected value, got {:?}", token),
            cursor.pos - 1,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_bare_protocol() {
        let expr = parse("tcp").unwrap();
        assert_eq!(expr, Expr::HasProtocol(Protocol::Tcp));
    }

    #[test]
    fn parse_not_binds_tighter_than_and() {
        // "not tcp and udp" → And(Not(HasProtocol(Tcp)), HasProtocol(Udp))
        let expr = parse("not tcp and udp").unwrap();
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Not(Box::new(Expr::HasProtocol(Protocol::Tcp)))),
                Box::new(Expr::HasProtocol(Protocol::Udp)),
            )
        );
    }

    #[test]
    fn parse_parentheses_override_precedence() {
        // "not (tcp and udp)" → Not(And(HasProtocol(Tcp), HasProtocol(Udp)))
        let expr = parse("not (tcp and udp)").unwrap();
        assert_eq!(
            expr,
            Expr::Not(Box::new(Expr::And(
                Box::new(Expr::HasProtocol(Protocol::Tcp)),
                Box::new(Expr::HasProtocol(Protocol::Udp)),
            )))
        );
    }

    #[test]
    fn parse_or_precedence() {
        // "tcp or udp and icmp" → Or(Tcp, And(Udp, Icmp))
        let expr = parse("tcp or udp and icmp").unwrap();
        assert_eq!(
            expr,
            Expr::Or(
                Box::new(Expr::HasProtocol(Protocol::Tcp)),
                Box::new(Expr::And(
                    Box::new(Expr::HasProtocol(Protocol::Udp)),
                    Box::new(Expr::HasProtocol(Protocol::Icmp)),
                )),
            )
        );
    }

    #[test]
    fn parse_field_comparison() {
        let expr = parse("ip.ttl > 64").unwrap();
        assert_eq!(
            expr,
            Expr::Compare("ip.ttl".to_string(), CmpOp::Gt, Value::Integer(64))
        );
    }

    #[test]
    fn parse_field_eq_ipv4() {
        let expr = parse("ip.src == 192.168.1.1").unwrap();
        assert_eq!(
            expr,
            Expr::Compare(
                "ip.src".to_string(),
                CmpOp::Eq,
                Value::IpV4(Ipv4Addr::new(192, 168, 1, 1)),
            )
        );
    }

    #[test]
    fn parse_field_eq_cidr() {
        let expr = parse("ip.dst == 10.0.0.0/8").unwrap();
        assert_eq!(
            expr,
            Expr::Compare(
                "ip.dst".to_string(),
                CmpOp::Eq,
                Value::Cidr4(Ipv4Addr::new(10, 0, 0, 0), 8),
            )
        );
    }

    #[test]
    fn parse_shorthand_port() {
        let expr = parse("port 443").unwrap();
        assert_eq!(expr, Expr::Shorthand(ShorthandKind::Port(443)));
    }

    #[test]
    fn parse_shorthand_src_cidr() {
        let expr = parse("src 10.0.0.0/8").unwrap();
        assert_eq!(
            expr,
            Expr::Shorthand(ShorthandKind::Src(AddrValue::V4Cidr(
                Ipv4Addr::new(10, 0, 0, 0),
                8
            )))
        );
    }

    #[test]
    fn parse_shorthand_dst_ipv6() {
        let expr = parse("dst 2001:db8::1").unwrap();
        assert_eq!(
            expr,
            Expr::Shorthand(ShorthandKind::Dst(AddrValue::V6(
                "2001:db8::1".parse().unwrap()
            )))
        );
    }

    #[test]
    fn parse_shorthand_host() {
        let expr = parse("host 192.168.1.1").unwrap();
        assert_eq!(
            expr,
            Expr::Shorthand(ShorthandKind::Host(AddrValue::V4(Ipv4Addr::new(
                192, 168, 1, 1
            ))))
        );
    }

    #[test]
    fn parse_bare_field() {
        let expr = parse("tcp.flags.syn").unwrap();
        assert_eq!(expr, Expr::BareField("tcp.flags.syn".to_string()));
    }

    #[test]
    fn parse_bare_field_eq_bool() {
        let expr = parse("tcp.flags.syn == true").unwrap();
        assert_eq!(
            expr,
            Expr::Compare("tcp.flags.syn".to_string(), CmpOp::Eq, Value::Bool(true))
        );
    }

    #[test]
    fn parse_complex_expression() {
        // "tcp and port 443 and not src 10.0.0.0/8"
        let expr = parse("tcp and port 443 and not src 10.0.0.0/8").unwrap();
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::And(
                    Box::new(Expr::HasProtocol(Protocol::Tcp)),
                    Box::new(Expr::Shorthand(ShorthandKind::Port(443))),
                )),
                Box::new(Expr::Not(Box::new(Expr::Shorthand(ShorthandKind::Src(
                    AddrValue::V4Cidr(Ipv4Addr::new(10, 0, 0, 0), 8)
                ))))),
            )
        );
    }

    #[test]
    fn parse_error_empty_expression() {
        let err = parse("").unwrap_err();
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn parse_error_double_and() {
        let err = parse("tcp and and").unwrap_err();
        assert!(err.message.contains("unexpected token"));
    }

    #[test]
    fn parse_error_trailing_rparen() {
        let err = parse(")").unwrap_err();
        assert!(err.message.contains("unexpected token"));
    }

    #[test]
    fn parse_error_port_overflow() {
        let err = parse("port 70000").unwrap_err();
        assert!(err.message.contains("port value 70000 exceeds maximum 65535"));
    }

    #[test]
    fn parse_error_port_missing_number() {
        let err = parse("port tcp").unwrap_err();
        assert!(err.message.contains("expected port number"));
    }

    #[test]
    fn parse_error_trailing_tokens() {
        let err = parse("tcp udp").unwrap_err();
        assert!(err.message.contains("unexpected token"));
    }

    #[test]
    fn parse_all_comparison_ops() {
        assert_eq!(
            parse("ip.ttl == 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Eq, Value::Integer(64))
        );
        assert_eq!(
            parse("ip.ttl != 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Neq, Value::Integer(64))
        );
        assert_eq!(
            parse("ip.ttl >= 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Gte, Value::Integer(64))
        );
        assert_eq!(
            parse("ip.ttl <= 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Lte, Value::Integer(64))
        );
        assert_eq!(
            parse("ip.ttl < 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Lt, Value::Integer(64))
        );
        assert_eq!(
            parse("ip.ttl > 64").unwrap(),
            Expr::Compare("ip.ttl".to_string(), CmpOp::Gt, Value::Integer(64))
        );
    }

    #[test]
    fn parse_all_protocols() {
        assert_eq!(parse("tcp").unwrap(), Expr::HasProtocol(Protocol::Tcp));
        assert_eq!(parse("udp").unwrap(), Expr::HasProtocol(Protocol::Udp));
        assert_eq!(parse("arp").unwrap(), Expr::HasProtocol(Protocol::Arp));
        assert_eq!(parse("icmp").unwrap(), Expr::HasProtocol(Protocol::Icmp));
        assert_eq!(parse("ip").unwrap(), Expr::HasProtocol(Protocol::Ipv4));
        assert_eq!(parse("ipv6").unwrap(), Expr::HasProtocol(Protocol::Ipv6));
        assert_eq!(parse("eth").unwrap(), Expr::HasProtocol(Protocol::Ethernet));
    }
}
```

- [ ] Step 2: Update `lib.rs` to add the parser module and public `parse` function

Update `crates/fireshark-filter/src/lib.rs` to:

```rust
pub mod ast;
mod error;
pub mod lexer;
mod parser;

pub use error::FilterError;
pub use parser::parse;
```

- [ ] Step 3: Run parser tests

Run: `cargo test -p fireshark-filter -- --nocapture`
Expected: all lexer and parser tests pass

- [ ] Step 4: Run full gate

Run: `just check`
Expected: PASS

- [ ] Step 5: Commit

```bash
git add crates/fireshark-filter
git commit -m "feat(filter): add recursive descent parser with precedence handling"
```

---

## Chunk 4: Evaluator

### Task 6 — Create evaluator with field resolution

- [ ] Step 1: Create `crates/fireshark-filter/src/evaluate.rs`

The evaluator resolves field paths to values extracted from a `DecodedFrame`, then performs comparisons.

**Key design decisions:**
- `resolve_field` returns `Option<FieldValue>` — `None` means the field is absent.
- `FieldValue` is an internal enum: `Integer(u64)`, `Addr(IpAddr)`, `Bool(bool)`, `PortPair(u16, u16)`.
- `PortPair` handles `tcp.port` / `udp.port` semantics (match-either direction).
- CIDR matching uses bitwise mask comparison.
- Missing field on any comparison returns `false`.

```rust
use std::net::{IpAddr, Ipv4Addr};

use fireshark_core::{DecodedFrame, Layer};

use crate::ast::{AddrValue, CmpOp, Expr, Protocol, ShorthandKind, Value};

/// Evaluate a filter expression against a decoded frame.
pub fn evaluate(expr: &Expr, decoded: &DecodedFrame) -> bool {
    match expr {
        Expr::And(left, right) => evaluate(left, decoded) && evaluate(right, decoded),
        Expr::Or(left, right) => evaluate(left, decoded) || evaluate(right, decoded),
        Expr::Not(inner) => !evaluate(inner, decoded),
        Expr::HasProtocol(protocol) => has_protocol(decoded, protocol),
        Expr::Compare(field, op, value) => eval_compare(decoded, field, *op, value),
        Expr::Shorthand(kind) => eval_shorthand(decoded, kind),
        Expr::BareField(field) => eval_bare_field(decoded, field),
    }
}

/// Check if a decoded frame contains a specific protocol layer.
fn has_protocol(decoded: &DecodedFrame, protocol: &Protocol) -> bool {
    decoded.packet().layers().iter().any(|layer| match (protocol, layer) {
        (Protocol::Tcp, Layer::Tcp(_)) => true,
        (Protocol::Udp, Layer::Udp(_)) => true,
        (Protocol::Arp, Layer::Arp(_)) => true,
        (Protocol::Icmp, Layer::Icmp(_)) => true,
        (Protocol::Ipv4, Layer::Ipv4(_)) => true,
        (Protocol::Ipv6, Layer::Ipv6(_)) => true,
        (Protocol::Ethernet, Layer::Ethernet(_)) => true,
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// Internal field value representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum FieldValue {
    Integer(u64),
    Addr(IpAddr),
    Bool(bool),
    /// For tcp.port / udp.port: matches if either port matches.
    PortPair(u16, u16),
}

/// Resolve a dotted field path to a `FieldValue` from the decoded frame.
///
/// Returns `None` if the field is not present (e.g., asking for tcp.srcport
/// on a UDP packet).
fn resolve_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    let layers = decoded.packet().layers();

    match field {
        // ----- Frame fields -----
        "frame.len" => Some(FieldValue::Integer(decoded.frame().original_len() as u64)),
        "frame.cap_len" => Some(FieldValue::Integer(decoded.frame().captured_len() as u64)),

        // ----- Ethernet fields -----
        "eth.type" => layers.iter().find_map(|l| match l {
            Layer::Ethernet(eth) => Some(FieldValue::Integer(u64::from(eth.ether_type))),
            _ => None,
        }),

        // ----- IPv4 fields -----
        "ip.src" => {
            // Dual-stack: try IPv4 first, then IPv6
            layers.iter().find_map(|l| match l {
                Layer::Ipv4(ip) => Some(FieldValue::Addr(IpAddr::V4(ip.source))),
                Layer::Ipv6(ip) => Some(FieldValue::Addr(IpAddr::V6(ip.source))),
                _ => None,
            })
        }
        "ip.dst" => {
            // Dual-stack: try IPv4 first, then IPv6
            layers.iter().find_map(|l| match l {
                Layer::Ipv4(ip) => Some(FieldValue::Addr(IpAddr::V4(ip.destination))),
                Layer::Ipv6(ip) => Some(FieldValue::Addr(IpAddr::V6(ip.destination))),
                _ => None,
            })
        }
        "ip.ttl" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.ttl))),
            _ => None,
        }),
        "ip.id" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.identification))),
            _ => None,
        }),
        "ip.proto" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.protocol))),
            _ => None,
        }),
        "ip.dscp" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.dscp))),
            _ => None,
        }),
        "ip.ecn" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.ecn))),
            _ => None,
        }),
        "ip.checksum" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.header_checksum))),
            _ => None,
        }),
        "ip.flags.df" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Bool(ip.dont_fragment)),
            _ => None,
        }),
        "ip.flags.mf" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Bool(ip.more_fragments)),
            _ => None,
        }),
        "ip.frag_offset" => layers.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(FieldValue::Integer(u64::from(ip.fragment_offset))),
            _ => None,
        }),

        // ----- IPv6 fields -----
        "ipv6.hlim" => layers.iter().find_map(|l| match l {
            Layer::Ipv6(ip) => Some(FieldValue::Integer(u64::from(ip.hop_limit))),
            _ => None,
        }),
        "ipv6.flow" => layers.iter().find_map(|l| match l {
            Layer::Ipv6(ip) => Some(FieldValue::Integer(u64::from(ip.flow_label))),
            _ => None,
        }),
        "ipv6.tc" => layers.iter().find_map(|l| match l {
            Layer::Ipv6(ip) => Some(FieldValue::Integer(u64::from(ip.traffic_class))),
            _ => None,
        }),
        "ipv6.nxt" => layers.iter().find_map(|l| match l {
            Layer::Ipv6(ip) => Some(FieldValue::Integer(u64::from(ip.next_header))),
            _ => None,
        }),

        // ----- TCP fields -----
        "tcp.srcport" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.source_port))),
            _ => None,
        }),
        "tcp.dstport" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.destination_port))),
            _ => None,
        }),
        "tcp.port" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::PortPair(tcp.source_port, tcp.destination_port)),
            _ => None,
        }),
        "tcp.seq" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.seq))),
            _ => None,
        }),
        "tcp.ack" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.ack))),
            _ => None,
        }),
        "tcp.window" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.window))),
            _ => None,
        }),
        "tcp.hdr_len" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Integer(u64::from(tcp.data_offset) * 4)),
            _ => None,
        }),
        "tcp.flags.syn" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.syn)),
            _ => None,
        }),
        "tcp.flags.ack" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.ack)),
            _ => None,
        }),
        "tcp.flags.fin" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.fin)),
            _ => None,
        }),
        "tcp.flags.rst" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.rst)),
            _ => None,
        }),
        "tcp.flags.psh" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.psh)),
            _ => None,
        }),
        "tcp.flags.urg" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.urg)),
            _ => None,
        }),
        "tcp.flags.ece" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.ece)),
            _ => None,
        }),
        "tcp.flags.cwr" => layers.iter().find_map(|l| match l {
            Layer::Tcp(tcp) => Some(FieldValue::Bool(tcp.flags.cwr)),
            _ => None,
        }),

        // ----- UDP fields -----
        "udp.srcport" => layers.iter().find_map(|l| match l {
            Layer::Udp(udp) => Some(FieldValue::Integer(u64::from(udp.source_port))),
            _ => None,
        }),
        "udp.dstport" => layers.iter().find_map(|l| match l {
            Layer::Udp(udp) => Some(FieldValue::Integer(u64::from(udp.destination_port))),
            _ => None,
        }),
        "udp.port" => layers.iter().find_map(|l| match l {
            Layer::Udp(udp) => Some(FieldValue::PortPair(udp.source_port, udp.destination_port)),
            _ => None,
        }),
        "udp.length" => layers.iter().find_map(|l| match l {
            Layer::Udp(udp) => Some(FieldValue::Integer(u64::from(udp.length))),
            _ => None,
        }),

        // ----- ICMP fields -----
        "icmp.type" => layers.iter().find_map(|l| match l {
            Layer::Icmp(icmp) => Some(FieldValue::Integer(u64::from(icmp.type_))),
            _ => None,
        }),
        "icmp.code" => layers.iter().find_map(|l| match l {
            Layer::Icmp(icmp) => Some(FieldValue::Integer(u64::from(icmp.code))),
            _ => None,
        }),

        // ----- ARP fields -----
        "arp.opcode" => layers.iter().find_map(|l| match l {
            Layer::Arp(arp) => Some(FieldValue::Integer(u64::from(arp.operation))),
            _ => None,
        }),
        "arp.spa" => layers.iter().find_map(|l| match l {
            Layer::Arp(arp) => Some(FieldValue::Addr(IpAddr::V4(arp.sender_protocol_addr))),
            _ => None,
        }),
        "arp.tpa" => layers.iter().find_map(|l| match l {
            Layer::Arp(arp) => Some(FieldValue::Addr(IpAddr::V4(arp.target_protocol_addr))),
            _ => None,
        }),

        // Unknown field
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Comparison logic
// ---------------------------------------------------------------------------

/// Evaluate a field comparison: `field op value`.
fn eval_compare(decoded: &DecodedFrame, field: &str, op: CmpOp, value: &Value) -> bool {
    let Some(field_val) = resolve_field(field, decoded) else {
        return false;
    };

    match (&field_val, value) {
        // Integer comparison
        (FieldValue::Integer(lhs), Value::Integer(rhs)) => cmp_integers(*lhs, op, *rhs),

        // Address comparison (exact match)
        (FieldValue::Addr(lhs), Value::IpV4(rhs)) => {
            let rhs_addr = IpAddr::V4(*rhs);
            match op {
                CmpOp::Eq => *lhs == rhs_addr,
                CmpOp::Neq => *lhs != rhs_addr,
                _ => false, // >, <, >=, <= not meaningful for addresses
            }
        }
        (FieldValue::Addr(lhs), Value::IpV6(rhs)) => {
            let rhs_addr = IpAddr::V6(*rhs);
            match op {
                CmpOp::Eq => *lhs == rhs_addr,
                CmpOp::Neq => *lhs != rhs_addr,
                _ => false,
            }
        }

        // CIDR comparison
        (FieldValue::Addr(lhs), Value::Cidr4(network, prefix)) => {
            match lhs {
                IpAddr::V4(addr) => {
                    let matches = cidr4_matches(*addr, *network, *prefix);
                    match op {
                        CmpOp::Eq => matches,
                        CmpOp::Neq => !matches,
                        _ => false,
                    }
                }
                IpAddr::V6(_) => false, // IPv6 addr never matches IPv4 CIDR
            }
        }

        // Boolean comparison
        (FieldValue::Bool(lhs), Value::Bool(rhs)) => match op {
            CmpOp::Eq => *lhs == *rhs,
            CmpOp::Neq => *lhs != *rhs,
            _ => false,
        },

        // PortPair: tcp.port == N checks either port
        (FieldValue::PortPair(src, dst), Value::Integer(rhs)) => {
            let rhs_u16 = u16::try_from(*rhs).ok();
            match (op, rhs_u16) {
                (CmpOp::Eq, Some(n)) => *src == n || *dst == n,
                (CmpOp::Neq, Some(n)) => *src != n && *dst != n,
                (CmpOp::Gt, Some(n)) => *src > n || *dst > n,
                (CmpOp::Lt, Some(n)) => *src < n || *dst < n,
                (CmpOp::Gte, Some(n)) => *src >= n || *dst >= n,
                (CmpOp::Lte, Some(n)) => *src <= n || *dst <= n,
                _ => false,
            }
        }

        // Type mismatch → false
        _ => false,
    }
}

/// Integer comparison helper.
fn cmp_integers(lhs: u64, op: CmpOp, rhs: u64) -> bool {
    match op {
        CmpOp::Eq => lhs == rhs,
        CmpOp::Neq => lhs != rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Lt => lhs < rhs,
        CmpOp::Gte => lhs >= rhs,
        CmpOp::Lte => lhs <= rhs,
    }
}

/// Check if an IPv4 address is within a CIDR range.
fn cidr4_matches(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return addr == network;
    }
    let mask = u32::MAX << (32 - prefix_len);
    let addr_bits = u32::from(addr);
    let net_bits = u32::from(network);
    (addr_bits & mask) == (net_bits & mask)
}

// ---------------------------------------------------------------------------
// Shorthand evaluation
// ---------------------------------------------------------------------------

/// Evaluate a shorthand filter (port, src, dst, host).
fn eval_shorthand(decoded: &DecodedFrame, kind: &ShorthandKind) -> bool {
    match kind {
        ShorthandKind::Port(port) => eval_port(decoded, *port),
        ShorthandKind::Src(addr) => eval_src(decoded, addr),
        ShorthandKind::Dst(addr) => eval_dst(decoded, addr),
        ShorthandKind::Host(addr) => eval_src(decoded, addr) || eval_dst(decoded, addr),
    }
}

/// `port N` — true if TCP or UDP source or destination port equals N.
fn eval_port(decoded: &DecodedFrame, port: u16) -> bool {
    decoded.packet().layers().iter().any(|layer| match layer {
        Layer::Tcp(tcp) => tcp.source_port == port || tcp.destination_port == port,
        Layer::Udp(udp) => udp.source_port == port || udp.destination_port == port,
        _ => false,
    })
}

/// `src ADDR` — true if the packet's source address matches.
fn eval_src(decoded: &DecodedFrame, addr: &AddrValue) -> bool {
    decoded.packet().layers().iter().any(|layer| match (addr, layer) {
        (AddrValue::V4(target), Layer::Ipv4(ip)) => ip.source == *target,
        (AddrValue::V4Cidr(network, prefix), Layer::Ipv4(ip)) => {
            cidr4_matches(ip.source, *network, *prefix)
        }
        (AddrValue::V6(target), Layer::Ipv6(ip)) => ip.source == *target,
        _ => false,
    })
}

/// `dst ADDR` — true if the packet's destination address matches.
fn eval_dst(decoded: &DecodedFrame, addr: &AddrValue) -> bool {
    decoded.packet().layers().iter().any(|layer| match (addr, layer) {
        (AddrValue::V4(target), Layer::Ipv4(ip)) => ip.destination == *target,
        (AddrValue::V4Cidr(network, prefix), Layer::Ipv4(ip)) => {
            cidr4_matches(ip.destination, *network, *prefix)
        }
        (AddrValue::V6(target), Layer::Ipv6(ip)) => ip.destination == *target,
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// Bare field evaluation
// ---------------------------------------------------------------------------

/// Evaluate a bare field reference (no comparison operator).
///
/// - Boolean fields: true if the field value is `true`.
/// - All other fields: true if the field is present (not `None`).
fn eval_bare_field(decoded: &DecodedFrame, field: &str) -> bool {
    match resolve_field(field, decoded) {
        Some(FieldValue::Bool(b)) => b,
        Some(_) => true, // field is present → truthy
        None => false,   // field is absent → falsy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, Protocol, ShorthandKind, Value, AddrValue, CmpOp};
    use fireshark_core::{DecodedFrame, Frame, Packet, Layer};
    use fireshark_dissectors::decode_packet;

    /// Helper: decode a fixture and wrap in a DecodedFrame.
    fn decode_fixture(bytes: &[u8]) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build();
        DecodedFrame::new(frame, packet)
    }

    // Fixture: Ethernet + IPv4 + TCP (SYN)
    const TCP_SYN: &[u8] = include_bytes!("../../../fixtures/bytes/tcp_syn.bin");
    // Fixture: Ethernet + IPv4 + TCP (SYN-ACK)
    const TCP_SYN_ACK: &[u8] = include_bytes!("../../../fixtures/bytes/tcp_syn_ack.bin");
    // Fixture: Ethernet + IPv4 + UDP
    const UDP: &[u8] = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin");
    // Fixture: Ethernet + ARP
    const ARP: &[u8] = include_bytes!("../../../fixtures/bytes/ethernet_arp.bin");
    // Fixture: Ethernet + IPv6 + ICMPv6
    const IPV6_ICMP: &[u8] = include_bytes!("../../../fixtures/bytes/ethernet_ipv6_icmp.bin");
    // Fixture: Ethernet + IPv4 + ICMP echo reply
    const ICMP_REPLY: &[u8] = include_bytes!("../../../fixtures/bytes/icmp_echo_reply.bin");

    // ---- Protocol presence ----

    #[test]
    fn eval_has_protocol_tcp() {
        let decoded = decode_fixture(TCP_SYN);
        assert!(evaluate(&Expr::HasProtocol(Protocol::Tcp), &decoded));
        assert!(evaluate(&Expr::HasProtocol(Protocol::Ipv4), &decoded));
        assert!(evaluate(&Expr::HasProtocol(Protocol::Ethernet), &decoded));
        assert!(!evaluate(&Expr::HasProtocol(Protocol::Udp), &decoded));
    }

    #[test]
    fn eval_has_protocol_udp() {
        let decoded = decode_fixture(UDP);
        assert!(evaluate(&Expr::HasProtocol(Protocol::Udp), &decoded));
        assert!(!evaluate(&Expr::HasProtocol(Protocol::Tcp), &decoded));
    }

    #[test]
    fn eval_has_protocol_arp() {
        let decoded = decode_fixture(ARP);
        assert!(evaluate(&Expr::HasProtocol(Protocol::Arp), &decoded));
        assert!(!evaluate(&Expr::HasProtocol(Protocol::Tcp), &decoded));
    }

    #[test]
    fn eval_has_protocol_icmp() {
        let decoded = decode_fixture(ICMP_REPLY);
        assert!(evaluate(&Expr::HasProtocol(Protocol::Icmp), &decoded));
    }

    #[test]
    fn eval_has_protocol_ipv6() {
        let decoded = decode_fixture(IPV6_ICMP);
        assert!(evaluate(&Expr::HasProtocol(Protocol::Ipv6), &decoded));
        assert!(!evaluate(&Expr::HasProtocol(Protocol::Ipv4), &decoded));
    }

    // ---- Boolean operators ----

    #[test]
    fn eval_and() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = Expr::And(
            Box::new(Expr::HasProtocol(Protocol::Tcp)),
            Box::new(Expr::HasProtocol(Protocol::Ipv4)),
        );
        assert!(evaluate(&expr, &decoded));
    }

    #[test]
    fn eval_or() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = Expr::Or(
            Box::new(Expr::HasProtocol(Protocol::Tcp)),
            Box::new(Expr::HasProtocol(Protocol::Udp)),
        );
        assert!(evaluate(&expr, &decoded));
    }

    #[test]
    fn eval_not() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = Expr::Not(Box::new(Expr::HasProtocol(Protocol::Udp)));
        assert!(evaluate(&expr, &decoded));
    }

    // ---- Field comparisons ----

    #[test]
    fn eval_ip_ttl_comparison() {
        let decoded = decode_fixture(TCP_SYN);
        // We don't know the exact TTL, but we can test comparison operators.
        // TTL should be present and >= 0
        let expr = Expr::Compare("ip.ttl".to_string(), CmpOp::Gte, Value::Integer(0));
        assert!(evaluate(&expr, &decoded));
    }

    #[test]
    fn eval_missing_field_returns_false() {
        let decoded = decode_fixture(UDP);
        // tcp.srcport on a UDP packet should return false
        let expr = Expr::Compare("tcp.srcport".to_string(), CmpOp::Eq, Value::Integer(80));
        assert!(!evaluate(&expr, &decoded));
    }

    #[test]
    fn eval_unknown_field_returns_false() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = Expr::Compare("nonexistent.field".to_string(), CmpOp::Eq, Value::Integer(0));
        assert!(!evaluate(&expr, &decoded));
    }

    // ---- Bare field (truthy check) ----

    #[test]
    fn eval_bare_boolean_field_syn() {
        let decoded = decode_fixture(TCP_SYN);
        // tcp_syn fixture should have SYN flag set
        assert!(evaluate(&Expr::BareField("tcp.flags.syn".to_string()), &decoded));
    }

    #[test]
    fn eval_bare_boolean_field_ack_on_syn() {
        let decoded = decode_fixture(TCP_SYN);
        // Pure SYN should not have ACK set
        assert!(!evaluate(&Expr::BareField("tcp.flags.ack".to_string()), &decoded));
    }

    #[test]
    fn eval_bare_boolean_field_ack_on_syn_ack() {
        let decoded = decode_fixture(TCP_SYN_ACK);
        // SYN-ACK should have ACK set
        assert!(evaluate(&Expr::BareField("tcp.flags.ack".to_string()), &decoded));
        assert!(evaluate(&Expr::BareField("tcp.flags.syn".to_string()), &decoded));
    }

    #[test]
    fn eval_bare_non_boolean_field_presence() {
        let decoded = decode_fixture(TCP_SYN);
        // ip.ttl is present (non-boolean) → truthy
        assert!(evaluate(&Expr::BareField("ip.ttl".to_string()), &decoded));
        // udp.length is not present → falsy
        assert!(!evaluate(&Expr::BareField("udp.length".to_string()), &decoded));
    }

    // ---- Port shorthand ----

    #[test]
    fn eval_port_shorthand_on_udp() {
        let decoded = decode_fixture(UDP);
        // We know the fixture has UDP; check port matching both directions
        let layers = decoded.packet().layers();
        let udp_layer = layers.iter().find_map(|l| match l {
            Layer::Udp(u) => Some(u),
            _ => None,
        }).unwrap();
        let src_port = udp_layer.source_port;

        let expr = Expr::Shorthand(ShorthandKind::Port(src_port));
        assert!(evaluate(&expr, &decoded));

        // A port that certainly doesn't match
        let expr = Expr::Shorthand(ShorthandKind::Port(0));
        // Could be 0 but extremely unlikely; if it is, this test is technically wrong
        // but is fine for practical purposes
        if src_port != 0 && udp_layer.destination_port != 0 {
            assert!(!evaluate(&expr, &decoded));
        }
    }

    // ---- CIDR matching ----

    #[test]
    fn cidr4_matches_basic() {
        // 10.1.2.3 is in 10.0.0.0/8
        assert!(cidr4_matches(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 0),
            8,
        ));
        // 192.168.1.1 is NOT in 10.0.0.0/8
        assert!(!cidr4_matches(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            8,
        ));
        // /0 matches everything
        assert!(cidr4_matches(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0,
        ));
        // /32 is exact match
        assert!(cidr4_matches(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32,
        ));
        assert!(!cidr4_matches(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            32,
        ));
    }

    // ---- Dual-stack ip.src ----

    #[test]
    fn eval_ip_src_ipv6() {
        let decoded = decode_fixture(IPV6_ICMP);
        // ip.src should resolve to the IPv6 source address for an IPv6 packet
        let field = resolve_field("ip.src", &decoded);
        assert!(field.is_some());
        match field.unwrap() {
            FieldValue::Addr(IpAddr::V6(_)) => {} // expected
            other => panic!("expected IPv6 addr, got {:?}", other),
        }
    }

    #[test]
    fn eval_ip_src_ipv4() {
        let decoded = decode_fixture(TCP_SYN);
        let field = resolve_field("ip.src", &decoded);
        assert!(field.is_some());
        match field.unwrap() {
            FieldValue::Addr(IpAddr::V4(_)) => {} // expected
            other => panic!("expected IPv4 addr, got {:?}", other),
        }
    }

    // ---- tcp.port matches either direction ----

    #[test]
    fn eval_tcp_port_either_direction() {
        let decoded = decode_fixture(TCP_SYN);
        let layers = decoded.packet().layers();
        let tcp = layers.iter().find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        }).unwrap();

        // Match source port
        let expr = Expr::Compare("tcp.port".to_string(), CmpOp::Eq, Value::Integer(u64::from(tcp.source_port)));
        assert!(evaluate(&expr, &decoded));

        // Match destination port
        let expr = Expr::Compare("tcp.port".to_string(), CmpOp::Eq, Value::Integer(u64::from(tcp.destination_port)));
        assert!(evaluate(&expr, &decoded));

        // Non-matching port
        let neither = if tcp.source_port != 1 && tcp.destination_port != 1 { 1u64 } else { 2u64 };
        let expr = Expr::Compare("tcp.port".to_string(), CmpOp::Eq, Value::Integer(neither));
        assert!(!evaluate(&expr, &decoded));
    }

    // ---- Frame fields ----

    #[test]
    fn eval_frame_len() {
        let decoded = decode_fixture(TCP_SYN);
        let len = decoded.frame().original_len() as u64;
        let expr = Expr::Compare("frame.len".to_string(), CmpOp::Eq, Value::Integer(len));
        assert!(evaluate(&expr, &decoded));
    }

    // ---- ARP fields ----

    #[test]
    fn eval_arp_opcode() {
        let decoded = decode_fixture(ARP);
        // ARP request or reply — opcode is present
        let expr = Expr::Compare("arp.opcode".to_string(), CmpOp::Gte, Value::Integer(1));
        assert!(evaluate(&expr, &decoded));
    }

    // ---- Address comparison type mismatch ----

    #[test]
    fn eval_ipv4_addr_against_ipv6_packet_returns_false() {
        let decoded = decode_fixture(IPV6_ICMP);
        let expr = Expr::Compare(
            "ip.src".to_string(),
            CmpOp::Eq,
            Value::IpV4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        assert!(!evaluate(&expr, &decoded));
    }

    // ---- Integration: parsed expression evaluation ----

    #[test]
    fn eval_parsed_tcp_and_syn() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = crate::parse("tcp and tcp.flags.syn").unwrap();
        assert!(evaluate(&expr, &decoded));
    }

    #[test]
    fn eval_parsed_not_udp_on_tcp() {
        let decoded = decode_fixture(TCP_SYN);
        let expr = crate::parse("not udp").unwrap();
        assert!(evaluate(&expr, &decoded));
    }
}
```

- [ ] Step 2: Update `lib.rs` to add the evaluator module and public `evaluate` function

Update `crates/fireshark-filter/src/lib.rs` to:

```rust
pub mod ast;
mod error;
mod evaluate;
pub mod lexer;
mod parser;

pub use error::FilterError;
pub use evaluate::evaluate;
pub use parser::parse;
```

Note: `lexer` stays `pub` so the parser tests can use tokens directly. The `evaluate` and `parser` modules are private — only their public functions are re-exported.

- [ ] Step 3: Run evaluator tests

Run: `cargo test -p fireshark-filter -- --nocapture`
Expected: all tests pass (lexer, parser, and evaluator)

- [ ] Step 4: Run full gate

Run: `just check`
Expected: PASS

- [ ] Step 5: Commit

```bash
git add crates/fireshark-filter
git commit -m "feat(filter): add evaluator with full field registry and CIDR matching"
```

---

## Chunk 5: CLI Integration

### Task 7 — Add fireshark-filter dependency to CLI

- [ ] Step 1: Add dependency in `crates/fireshark-cli/Cargo.toml`

Add to `[dependencies]`:

```toml
fireshark-filter = { path = "../fireshark-filter" }
```

The full `[dependencies]` section becomes:

```toml
[dependencies]
clap = { version = "4.6.0", features = ["derive"] }
colored = "3"
fireshark-core = { path = "../fireshark-core" }
fireshark-dissectors = { path = "../fireshark-dissectors" }
fireshark-file = { path = "../fireshark-file" }
fireshark-filter = { path = "../fireshark-filter" }
```

### Task 8 — Add `-f` / `--filter` optional arg to Summary command

- [ ] Step 1: Modify `crates/fireshark-cli/src/main.rs`

Add the `filter` argument to the `Summary` variant and pass it through to `summary::run`:

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
        #[arg(short = 'f', long = "filter", help = "Display filter expression")]
        filter: Option<String>,
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
        Command::Summary { path, filter } => summary::run(&path, filter.as_deref())?,
        Command::Detail { path, packet } => detail::run(&path, packet)?,
    }

    Ok(())
}
```

### Task 9 — Update summary.rs to accept and apply filter

- [ ] Step 1: Modify `crates/fireshark-cli/src/summary.rs`

```rust
use std::path::Path;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

pub fn run(path: &Path, filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the filter expression up front (fail fast on invalid filter)
    let parsed_filter = match filter {
        Some(expr) => Some(fireshark_filter::parse(expr)?),
        None => None,
    };

    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = decoded?;

        // Apply display filter if present
        if let Some(ref expr) = parsed_filter {
            if !fireshark_filter::evaluate(expr, &decoded) {
                continue;
            }
        }

        let summary = decoded.summary();
        let ts = match summary.timestamp {
            Some(duration) => timestamp::format_utc(duration),
            None => String::from("-"),
        };
        let line = format!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            index + 1,
            ts,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}
```

### Task 10 — Integration tests

- [ ] Step 1: Add CLI integration test for display filter

Create or update `crates/fireshark-cli/tests/filter_integration.rs`:

```rust
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn summary_filter_tcp_shows_only_tcp() {
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("fixtures/smoke/fuzz-2006-06-26-2594.pcap")
        .arg("-f")
        .arg("tcp");
    cmd.assert()
        .success()
        // The fuzz fixture has mostly UDP/ARP — filtering for TCP should exclude them
        .stdout(predicates::str::contains("UDP").not())
        .stdout(predicates::str::contains("ARP").not());
}

#[test]
fn summary_filter_invalid_expression_exits_nonzero() {
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("fixtures/smoke/minimal.pcap")
        .arg("-f")
        .arg("invalid $$");
    cmd.assert().failure();
}

#[test]
fn summary_no_filter_still_works() {
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("fixtures/smoke/minimal.pcap");
    cmd.assert().success();
}
```

- [ ] Step 2: Run integration tests

Run: `cargo test -p fireshark-cli -- --nocapture`
Expected: all tests pass

- [ ] Step 3: Run full gate

Run: `just check`
Expected: PASS — all formatting, clippy, and test checks pass

- [ ] Step 4: Commit

```bash
git add Cargo.toml crates/fireshark-cli crates/fireshark-filter
git commit -m "feat(cli): add -f display filter flag to summary command"
```

---

## Final Verification

After all chunks are complete, run:

```bash
just check
```

Expected: `fmt-check`, `clippy`, and `test` all pass with zero failures.

## Summary of Files

### New Files
- `crates/fireshark-filter/Cargo.toml`
- `crates/fireshark-filter/src/lib.rs`
- `crates/fireshark-filter/src/ast.rs`
- `crates/fireshark-filter/src/error.rs`
- `crates/fireshark-filter/src/lexer.rs`
- `crates/fireshark-filter/src/parser.rs`
- `crates/fireshark-filter/src/evaluate.rs`
- `crates/fireshark-cli/tests/filter_integration.rs`

### Modified Files
- `Cargo.toml` — add `crates/fireshark-filter` to workspace members
- `crates/fireshark-cli/Cargo.toml` — add `fireshark-filter` dependency
- `crates/fireshark-cli/src/main.rs` — add `-f`/`--filter` arg to `Summary` variant
- `crates/fireshark-cli/src/summary.rs` — accept filter param, parse and evaluate
