use crate::FilterError;
use crate::ast::{AddrValue, CmpOp, Expr, Protocol, ShorthandKind, Value};
use crate::lexer::{SpannedToken, Token, tokenize_spanned};

/// Maximum nesting depth for parenthesized and unary expressions.
const MAX_DEPTH: usize = 128;

/// Parse a display filter expression string into an AST.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    if input.trim().is_empty() {
        return Err(FilterError::new("empty filter expression", 0));
    }
    let tokens = tokenize_spanned(input)?;
    let mut cursor = Cursor::new(&tokens, input.len());
    let expr = parse_expr(&mut cursor)?;
    if cursor.pos < tokens.len() {
        return Err(FilterError::new(
            format!("unexpected token {:?}", tokens[cursor.pos].token),
            tokens[cursor.pos].position,
        ));
    }
    Ok(expr)
}

struct Cursor<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
    input_len: usize,
    depth: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [SpannedToken], input_len: usize) -> Self {
        Self {
            tokens,
            pos: 0,
            input_len,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|token| &token.token)
    }

    fn advance(&mut self) -> Option<&SpannedToken> {
        let token = self.tokens.get(self.pos);
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn current_position(&self) -> usize {
        self.tokens
            .get(self.pos)
            .map_or(self.input_len, |token| token.position)
    }

    fn expect_advance(&mut self, context: &str) -> Result<&SpannedToken, FilterError> {
        if self.pos >= self.tokens.len() {
            return Err(FilterError::new(
                format!("unexpected end of expression, expected {context}"),
                self.input_len,
            ));
        }
        let token = &self.tokens[self.pos];
        self.pos += 1;
        Ok(token)
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
        cursor.depth += 1;
        if cursor.depth > MAX_DEPTH {
            return Err(FilterError::new(
                "expression exceeds maximum nesting depth",
                cursor.current_position(),
            ));
        }
        cursor.advance();
        let inner = parse_unary(cursor)?;
        cursor.depth -= 1;
        return Ok(Expr::Not(Box::new(inner)));
    }
    parse_atom(cursor)
}

fn parse_atom(cursor: &mut Cursor<'_>) -> Result<Expr, FilterError> {
    let token = cursor.peek().ok_or_else(|| {
        FilterError::new("unexpected end of expression", cursor.current_position())
    })?;

    match token {
        // Parenthesized expression
        Token::LParen => {
            cursor.depth += 1;
            if cursor.depth > MAX_DEPTH {
                return Err(FilterError::new(
                    "expression exceeds maximum nesting depth",
                    cursor.current_position(),
                ));
            }
            cursor.advance();
            let expr = parse_expr(cursor)?;
            cursor.depth -= 1;
            match cursor.peek() {
                Some(Token::RParen) => {
                    cursor.advance();
                    Ok(expr)
                }
                _ => Err(FilterError::new(
                    "expected closing ')'",
                    cursor.current_position(),
                )),
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
        Token::Dns => {
            cursor.advance();
            Ok(Expr::HasProtocol(Protocol::Dns))
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
                Some(SpannedToken {
                    token: Token::Ident(s),
                    ..
                }) => s.clone(),
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
            cursor.current_position(),
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
    match &token.token {
        Token::Integer(n) => u16::try_from(*n).map_err(|_| {
            FilterError::new(
                format!("port value {n} exceeds maximum 65535"),
                token.position,
            )
        }),
        _ => Err(FilterError::new(
            format!("expected port number, got {:?}", token.token),
            token.position,
        )),
    }
}

/// Parse an address value for src/dst/host shorthands.
fn parse_addr_value(cursor: &mut Cursor<'_>) -> Result<AddrValue, FilterError> {
    let token = cursor.expect_advance("address")?;
    match &token.token {
        Token::IpV4Addr(addr) => Ok(AddrValue::V4(*addr)),
        Token::Cidr4(addr, prefix) => Ok(AddrValue::V4Cidr(*addr, *prefix)),
        Token::IpV6Addr(addr) => Ok(AddrValue::V6(*addr)),
        _ => Err(FilterError::new(
            format!("expected address, got {:?}", token.token),
            token.position,
        )),
    }
}

/// Parse a value on the right-hand side of a comparison.
fn parse_value(cursor: &mut Cursor<'_>) -> Result<Value, FilterError> {
    let token = cursor.expect_advance("value")?;
    match &token.token {
        Token::Integer(n) => Ok(Value::Integer(*n)),
        Token::IpV4Addr(addr) => Ok(Value::IpV4(*addr)),
        Token::IpV6Addr(addr) => Ok(Value::IpV6(*addr)),
        Token::Cidr4(addr, prefix) => Ok(Value::Cidr4(*addr, *prefix)),
        Token::Bool(b) => Ok(Value::Bool(*b)),
        _ => Err(FilterError::new(
            format!("expected value, got {:?}", token.token),
            token.position,
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
        // "not tcp and udp" -> And(Not(HasProtocol(Tcp)), HasProtocol(Udp))
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
        // "not (tcp and udp)" -> Not(And(HasProtocol(Tcp), HasProtocol(Udp)))
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
        // "tcp or udp and icmp" -> Or(Tcp, And(Udp, Icmp))
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
    fn parse_or_simple() {
        let expr = parse("tcp or udp").unwrap();
        assert_eq!(
            expr,
            Expr::Or(
                Box::new(Expr::HasProtocol(Protocol::Tcp)),
                Box::new(Expr::HasProtocol(Protocol::Udp)),
            )
        );
    }

    #[test]
    fn parse_paren_or_and_port() {
        let expr = parse("(tcp or udp) and port 53").unwrap();
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Or(
                    Box::new(Expr::HasProtocol(Protocol::Tcp)),
                    Box::new(Expr::HasProtocol(Protocol::Udp)),
                )),
                Box::new(Expr::Shorthand(ShorthandKind::Port(53))),
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
        assert_eq!(err.position, 8);
    }

    #[test]
    fn parse_error_trailing_rparen() {
        let err = parse(")").unwrap_err();
        assert!(err.message.contains("unexpected token"));
    }

    #[test]
    fn parse_error_port_overflow() {
        let err = parse("port 70000").unwrap_err();
        assert!(
            err.message
                .contains("port value 70000 exceeds maximum 65535")
        );
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
        assert_eq!(parse("dns").unwrap(), Expr::HasProtocol(Protocol::Dns));
    }

    #[test]
    fn parse_error_deeply_nested_parens() {
        let input = "(".repeat(200) + "tcp" + &")".repeat(200);
        let err = parse(&input).unwrap_err();
        assert!(err.message.contains("nesting depth"));
    }

    #[test]
    fn parse_error_deeply_nested_not() {
        let input = "not ".repeat(200) + "tcp";
        let err = parse(&input).unwrap_err();
        assert!(err.message.contains("nesting depth"));
    }
}
