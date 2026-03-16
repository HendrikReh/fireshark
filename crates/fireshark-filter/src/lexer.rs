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
    Dns,
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SpannedToken {
    pub(crate) token: Token,
    pub(crate) position: usize,
}

/// Tokenize a display filter expression string.
pub fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    Ok(tokenize_spanned(input)?
        .into_iter()
        .map(|token| token.token)
        .collect())
}

pub(crate) fn tokenize_spanned(input: &str) -> Result<Vec<SpannedToken>, FilterError> {
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
                tokens.push(SpannedToken {
                    token: Token::LParen,
                    position: start,
                });
                pos += 1;
            }
            b')' => {
                tokens.push(SpannedToken {
                    token: Token::RParen,
                    position: start,
                });
                pos += 1;
            }
            b'!' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(SpannedToken {
                    token: Token::Neq,
                    position: start,
                });
                pos += 2;
            }
            b'=' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(SpannedToken {
                    token: Token::Eq,
                    position: start,
                });
                pos += 2;
            }
            b'>' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(SpannedToken {
                    token: Token::Gte,
                    position: start,
                });
                pos += 2;
            }
            b'<' if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' => {
                tokens.push(SpannedToken {
                    token: Token::Lte,
                    position: start,
                });
                pos += 2;
            }
            b'>' => {
                tokens.push(SpannedToken {
                    token: Token::Gt,
                    position: start,
                });
                pos += 1;
            }
            b'<' => {
                tokens.push(SpannedToken {
                    token: Token::Lt,
                    position: start,
                });
                pos += 1;
            }
            b if b.is_ascii_digit() => {
                let token = scan_number(input, &mut pos)?;
                tokens.push(SpannedToken {
                    token,
                    position: start,
                });
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let token = scan_identifier(input, &mut pos)?;
                tokens.push(SpannedToken {
                    token,
                    position: start,
                });
            }
            _ => {
                return Err(FilterError::new(
                    format!(
                        "unexpected character '{}'",
                        input[start..start + 1].chars().next().unwrap_or('?')
                    ),
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

    // Hex integer (0x prefix)
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(Token::Integer)
            .map_err(|_| FilterError::new(format!("invalid hex integer '{text}'"), start));
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
    // Examples: fe80::1, ff02::1, dead::beef
    // Only hex-letter-starting addresses reach here (digit-starting go to scan_number)
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
        "dns" => Token::Dns,
        "port" => Token::Port,
        "src" => Token::Src,
        "dst" => Token::Dst,
        "host" => Token::Host,
        "true" => Token::Bool(true),
        "false" => Token::Bool(false),
        _ => Token::Ident(text.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
            vec![Token::Src, Token::Cidr4(Ipv4Addr::new(10, 0, 0, 0), 8),]
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
            vec![Token::Dst, Token::IpV4Addr(Ipv4Addr::new(192, 168, 1, 1)),]
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

    #[test]
    fn tokenize_ip_dst_eq_ipv4() {
        let tokens = tokenize("ip.dst == 192.168.1.1").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("ip.dst".to_string()),
                Token::Eq,
                Token::IpV4Addr(Ipv4Addr::new(192, 168, 1, 1)),
            ]
        );
    }

    #[test]
    fn tokenize_true_literal() {
        let tokens = tokenize("true").unwrap();
        assert_eq!(tokens, vec![Token::Bool(true)]);
    }

    #[test]
    fn tokenize_error_bare_bang() {
        let err = tokenize("!").unwrap_err();
        assert!(err.message.contains("unexpected character"));
    }

    #[test]
    fn tokenize_error_dollar_signs() {
        let err = tokenize("$$$").unwrap_err();
        assert!(err.message.contains("unexpected character"));
    }

    #[test]
    fn tokenize_dns_keyword() {
        let tokens = tokenize("dns").unwrap();
        assert_eq!(tokens, vec![Token::Dns]);
    }

    #[test]
    fn tokenize_dns_field_is_ident() {
        let tokens = tokenize("dns.id").unwrap();
        assert_eq!(tokens, vec![Token::Ident("dns.id".to_string())]);
    }

    #[test]
    fn tokenize_hex_integer() {
        let tokens = tokenize("dns.id == 0x1234").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("dns.id".to_string()),
                Token::Eq,
                Token::Integer(0x1234),
            ]
        );
    }
}
