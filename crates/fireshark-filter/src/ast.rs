use std::net::{Ipv4Addr, Ipv6Addr};

/// A compiled regex pattern stored in the AST.
///
/// Wraps [`regex::Regex`] with manual `PartialEq` + `Eq` based on the
/// original pattern string so that the `Value` enum can remain `PartialEq`.
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

/// A display filter expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    HasProtocol(Protocol),
    Compare(FieldPath, CmpOp, Value),
    Shorthand(ShorthandKind),
    /// Truthy check: boolean field -> true test; non-boolean -> presence check.
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
    Dns,
    Tls,
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
    Contains,
    Matches,
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Integer(u64),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Cidr4(Ipv4Addr, u8),
    Bool(bool),
    Str(String),
    Regex(RegexPattern),
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
