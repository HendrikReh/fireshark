use std::net::{IpAddr, Ipv4Addr};

use fireshark_core::{DecodedFrame, Layer};

use crate::ast::{AddrValue, CmpOp, Expr, Protocol, ShorthandKind, Value};
use crate::fields::{FieldValue, resolve_field};

/// Evaluate a display filter expression against a decoded frame.
pub fn evaluate(expr: &Expr, decoded: &DecodedFrame) -> bool {
    match expr {
        Expr::And(l, r) => evaluate(l, decoded) && evaluate(r, decoded),
        Expr::Or(l, r) => evaluate(l, decoded) || evaluate(r, decoded),
        Expr::Not(e) => !evaluate(e, decoded),
        Expr::HasProtocol(p) => has_protocol(p, decoded),
        Expr::Compare(field, op, value) => compare_field(field, op, value, decoded),
        Expr::Shorthand(kind) => evaluate_shorthand(kind, decoded),
        Expr::BareField(field) => evaluate_bare_field(field, decoded),
    }
}

fn has_protocol(protocol: &Protocol, decoded: &DecodedFrame) -> bool {
    decoded
        .packet()
        .layers()
        .iter()
        .any(|layer| match protocol {
            Protocol::Tcp => matches!(layer, Layer::Tcp(_)),
            Protocol::Udp => matches!(layer, Layer::Udp(_)),
            Protocol::Arp => matches!(layer, Layer::Arp(_)),
            Protocol::Icmp => matches!(layer, Layer::Icmp(_)),
            Protocol::Ipv4 => matches!(layer, Layer::Ipv4(_)),
            Protocol::Ipv6 => matches!(layer, Layer::Ipv6(_)),
            Protocol::Ethernet => matches!(layer, Layer::Ethernet(_)),
            Protocol::Dns => matches!(layer, Layer::Dns(_)),
            Protocol::Tls => {
                matches!(layer, Layer::TlsClientHello(_) | Layer::TlsServerHello(_))
            }
            Protocol::Http => matches!(layer, Layer::Http(_)),
        })
}

fn compare_field(field: &str, op: &CmpOp, value: &Value, decoded: &DecodedFrame) -> bool {
    match resolve_field(field, decoded) {
        Some(resolved) => compare_values(&resolved, op, value),
        None => false,
    }
}

fn evaluate_shorthand(kind: &ShorthandKind, decoded: &DecodedFrame) -> bool {
    match kind {
        ShorthandKind::Port(n) => shorthand_port(*n, decoded),
        ShorthandKind::Src(addr) => shorthand_src(addr, decoded),
        ShorthandKind::Dst(addr) => shorthand_dst(addr, decoded),
        ShorthandKind::Host(addr) => shorthand_src(addr, decoded) || shorthand_dst(addr, decoded),
    }
}

fn shorthand_port(port: u16, decoded: &DecodedFrame) -> bool {
    for layer in decoded.packet().layers() {
        match layer {
            Layer::Tcp(l) => {
                if l.source_port == port || l.destination_port == port {
                    return true;
                }
            }
            Layer::Udp(l) => {
                if l.source_port == port || l.destination_port == port {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn shorthand_src(addr: &AddrValue, decoded: &DecodedFrame) -> bool {
    match resolve_ip_src(decoded) {
        Some(resolved) => addr_matches(&resolved, addr),
        None => false,
    }
}

fn shorthand_dst(addr: &AddrValue, decoded: &DecodedFrame) -> bool {
    match resolve_ip_dst(decoded) {
        Some(resolved) => addr_matches(&resolved, addr),
        None => false,
    }
}

fn resolve_ip_src(decoded: &DecodedFrame) -> Option<IpAddr> {
    for layer in decoded.packet().layers() {
        match layer {
            Layer::Ipv4(l) => return Some(IpAddr::V4(l.source)),
            Layer::Ipv6(l) => return Some(IpAddr::V6(l.source)),
            _ => {}
        }
    }
    None
}

fn resolve_ip_dst(decoded: &DecodedFrame) -> Option<IpAddr> {
    for layer in decoded.packet().layers() {
        match layer {
            Layer::Ipv4(l) => return Some(IpAddr::V4(l.destination)),
            Layer::Ipv6(l) => return Some(IpAddr::V6(l.destination)),
            _ => {}
        }
    }
    None
}

fn addr_matches(ip: &IpAddr, addr: &AddrValue) -> bool {
    match (ip, addr) {
        (IpAddr::V4(actual), AddrValue::V4(expected)) => actual == expected,
        (IpAddr::V4(actual), AddrValue::V4Cidr(network, prefix)) => {
            cidr4_matches(*actual, *network, *prefix)
        }
        (IpAddr::V6(actual), AddrValue::V6(expected)) => actual == expected,
        _ => false,
    }
}

fn evaluate_bare_field(field: &str, decoded: &DecodedFrame) -> bool {
    match resolve_field(field, decoded) {
        Some(FieldValue::Bool(b)) => b,
        Some(_) => true,
        None => false,
    }
}

fn compare_values(left: &FieldValue, op: &CmpOp, right: &Value) -> bool {
    match (left, right) {
        (FieldValue::Integer(l), Value::Integer(r)) => compare_integers(*l, op, *r),
        (FieldValue::Address(addr), Value::IpV4(r)) => {
            let r_addr = IpAddr::V4(*r);
            match op {
                CmpOp::Eq => *addr == r_addr,
                CmpOp::Neq => *addr != r_addr,
                _ => false,
            }
        }
        (FieldValue::Address(addr), Value::IpV6(r)) => {
            let r_addr = IpAddr::V6(*r);
            match op {
                CmpOp::Eq => *addr == r_addr,
                CmpOp::Neq => *addr != r_addr,
                _ => false,
            }
        }
        (FieldValue::Address(addr), Value::Cidr4(network, prefix)) => match addr {
            IpAddr::V4(v4) => match op {
                CmpOp::Eq => cidr4_matches(*v4, *network, *prefix),
                CmpOp::Neq => !cidr4_matches(*v4, *network, *prefix),
                _ => false,
            },
            IpAddr::V6(_) => false,
        },
        (FieldValue::Bool(l), Value::Bool(r)) => match op {
            CmpOp::Eq => *l == *r,
            CmpOp::Neq => *l != *r,
            _ => false,
        },
        (FieldValue::PortPair(src, dst), Value::Integer(n)) => {
            let s = u64::from(*src);
            let d = u64::from(*dst);
            match op {
                CmpOp::Eq => s == *n || d == *n,
                CmpOp::Neq => s != *n && d != *n,
                CmpOp::Gt => s > *n || d > *n,
                CmpOp::Lt => s < *n || d < *n,
                CmpOp::Gte => s >= *n || d >= *n,
                CmpOp::Lte => s <= *n || d <= *n,
                _ => false,
            }
        }
        // String exact equality/inequality
        (FieldValue::Str(s), Value::Str(v)) => match op {
            CmpOp::Eq => s == v,
            CmpOp::Neq => s != v,
            CmpOp::Contains => s.to_ascii_lowercase().contains(&v.to_ascii_lowercase()),
            _ => false,
        },
        // String contains (case-insensitive) on Str field
        (FieldValue::Str(s), Value::Regex(re)) => match op {
            CmpOp::Matches => re.compiled.is_match(s),
            _ => false,
        },
        // Fallback: convert any field value to string for contains/matches
        (field_val, Value::Str(needle)) if *op == CmpOp::Contains => {
            let s = field_value_to_string(field_val);
            s.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        }
        (field_val, Value::Regex(re)) if *op == CmpOp::Matches => {
            let s = field_value_to_string(field_val);
            re.compiled.is_match(&s)
        }
        // Type mismatches
        _ => false,
    }
}

/// Convert any field value to its string representation for use with
/// `contains` and `matches` operators on non-string fields.
fn field_value_to_string(val: &FieldValue) -> String {
    match val {
        FieldValue::Integer(n) => n.to_string(),
        FieldValue::Address(a) => a.to_string(),
        FieldValue::Bool(b) => b.to_string(),
        FieldValue::PortPair(s, d) => format!("{s},{d}"),
        FieldValue::Str(s) => s.clone(),
    }
}

fn compare_integers(left: u64, op: &CmpOp, right: u64) -> bool {
    match op {
        CmpOp::Eq => left == right,
        CmpOp::Neq => left != right,
        CmpOp::Gt => left > right,
        CmpOp::Lt => left < right,
        CmpOp::Gte => left >= right,
        CmpOp::Lte => left <= right,
        CmpOp::Contains | CmpOp::Matches => false,
    }
}

fn cidr4_matches(addr: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    let addr_bits = u32::from(addr);
    let net_bits = u32::from(network);
    (addr_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use fireshark_core::{DecodedFrame, Frame};
    use fireshark_dissectors::decode_packet;

    /// Helper: build a DecodedFrame from raw ethernet bytes.
    fn decoded_from_bytes(bytes: &[u8]) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
        DecodedFrame::new(frame, packet)
    }

    /// Helper: parse a filter string and run the evaluator against a decoded frame.
    fn run_filter(filter: &str, decoded: &DecodedFrame) -> bool {
        let expr = parse(filter).unwrap();
        evaluate(&expr, decoded)
    }

    // --- TCP fixture: ethernet_ipv4_tcp.bin ---
    // Layers: Ethernet + IPv4(src=192.0.2.10, dst=198.51.100.20, ttl=64) + TCP(51514->443, SYN)

    #[test]
    fn has_protocol_tcp_on_tcp_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp", &decoded));
    }

    #[test]
    fn has_protocol_udp_on_tcp_packet_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("udp", &decoded));
    }

    #[test]
    fn ip_ttl_equals_64() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("ip.ttl == 64", &decoded));
    }

    #[test]
    fn ip_ttl_greater_than_100_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("ip.ttl > 100", &decoded));
    }

    #[test]
    fn tcp_flags_syn_bare_field() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.flags.syn", &decoded));
    }

    #[test]
    fn port_443_shorthand() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("port 443", &decoded));
    }

    #[test]
    fn port_53_on_tcp_443_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("port 53", &decoded));
    }

    #[test]
    fn src_192_0_2_10() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("src 192.0.2.10", &decoded));
    }

    #[test]
    fn ip_dst_cidr_10_0_0_0_slash_8_on_198_dst_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("ip.dst == 10.0.0.0/8", &decoded));
    }

    #[test]
    fn tcp_port_eq_443() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.port == 443", &decoded));
    }

    #[test]
    fn tcp_port_neq_443() {
        // tcp.port != 443 means: src!=443 AND dst!=443
        // src=51514, dst=443 -> 51514!=443 is true but 443!=443 is false -> false
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("tcp.port != 443", &decoded));
    }

    #[test]
    fn missing_field_tcp_port_on_udp_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp.bin"
        ));
        assert!(!run_filter("tcp.port == 80", &decoded));
    }

    #[test]
    fn not_tcp_on_tcp_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("not tcp", &decoded));
    }

    // --- UDP fixture: ethernet_ipv4_udp.bin ---
    // Layers: Ethernet + IPv4 + UDP(5353->53)

    #[test]
    fn has_protocol_udp_on_udp_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp.bin"
        ));
        assert!(run_filter("udp", &decoded));
    }

    #[test]
    fn udp_port_53_shorthand() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp.bin"
        ));
        assert!(run_filter("port 53", &decoded));
    }

    #[test]
    fn udp_dstport_value() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp.bin"
        ));
        assert!(run_filter("udp.dstport == 53", &decoded));
    }

    // --- ARP fixture ---

    #[test]
    fn has_protocol_arp() {
        let decoded =
            decoded_from_bytes(include_bytes!("../../../fixtures/bytes/ethernet_arp.bin"));
        assert!(run_filter("arp", &decoded));
    }

    #[test]
    fn arp_opcode_value() {
        let decoded =
            decoded_from_bytes(include_bytes!("../../../fixtures/bytes/ethernet_arp.bin"));
        assert!(run_filter("arp.opcode == 1", &decoded));
    }

    // --- CIDR matching ---

    #[test]
    fn cidr4_match_in_range() {
        assert!(cidr4_matches(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 0),
            8
        ));
    }

    #[test]
    fn cidr4_no_match_out_of_range() {
        assert!(!cidr4_matches(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            8
        ));
    }

    #[test]
    fn cidr4_prefix_zero_matches_everything() {
        assert!(cidr4_matches(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
    }

    #[test]
    fn cidr4_prefix_32_exact_match() {
        assert!(cidr4_matches(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
        assert!(!cidr4_matches(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
    }

    // --- Compound expressions ---

    #[test]
    fn and_expression() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp and ip.ttl == 64", &decoded));
    }

    #[test]
    fn or_expression() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("udp or tcp", &decoded));
    }

    #[test]
    fn complex_filter() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter(
            "tcp and port 443 and not src 10.0.0.0/8",
            &decoded
        ));
    }

    // --- Bool comparison ---

    #[test]
    fn tcp_flags_syn_eq_true() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.flags.syn == true", &decoded));
    }

    #[test]
    fn tcp_flags_ack_bare_field_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("tcp.flags.ack", &decoded));
    }

    // --- Frame fields ---

    #[test]
    fn frame_len_matches_data_length() {
        let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
        let decoded = decoded_from_bytes(bytes);
        let filter = format!("frame.len == {}", bytes.len());
        assert!(run_filter(&filter, &decoded));
    }

    // --- IP address comparison ---

    #[test]
    fn ip_src_exact_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("ip.src == 192.0.2.10", &decoded));
    }

    #[test]
    fn ip_src_exact_mismatch() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("ip.src == 1.2.3.4", &decoded));
    }

    #[test]
    fn ip_dst_cidr_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        // dst is 198.51.100.20, so 198.51.100.0/24 should match
        assert!(run_filter("ip.dst == 198.51.100.0/24", &decoded));
    }

    // --- Ethernet ---

    #[test]
    fn has_protocol_ethernet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("eth", &decoded));
    }

    #[test]
    fn eth_type_ipv4() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        // IPv4 ether_type = 0x0800 = 2048
        assert!(run_filter("eth.type == 2048", &decoded));
    }

    // --- DNS fixture: ethernet_ipv4_udp_dns.bin ---
    // Layers: Ethernet + IPv4 + UDP + DNS(id=0x1234, query, opcode=0, qcount=1, acount=0, qtype=A)

    #[test]
    fn has_protocol_dns_on_dns_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns", &decoded));
    }

    #[test]
    fn has_protocol_dns_on_tcp_only_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("dns", &decoded));
    }

    #[test]
    fn dns_id_hex_comparison() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.id == 0x1234", &decoded));
    }

    #[test]
    fn dns_qr_bare_field_false_for_query() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        // Fixture is a query (is_response=false), so bare dns.qr evaluates to false
        assert!(!run_filter("dns.qr", &decoded));
    }

    #[test]
    fn dns_not_qr_true_for_query() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("not dns.qr", &decoded));
    }

    #[test]
    fn dns_qtype_eq_1_for_a_record() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.qtype == 1", &decoded));
    }

    // --- IPv6 fixture: ethernet_ipv6_icmp.bin ---

    #[test]
    fn has_protocol_ipv6_on_ipv6_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv6_icmp.bin"
        ));
        assert!(run_filter("ipv6", &decoded));
    }

    #[test]
    fn ipv6_ip_src_resolved() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv6_icmp.bin"
        ));
        // ip.src should resolve for IPv6 packets too
        let src = resolve_ip_src(&decoded);
        assert!(src.is_some());
    }

    #[test]
    fn ipv6_hlim_field() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv6_icmp.bin"
        ));
        // ipv6.hlim should be resolvable
        let field = resolve_field("ipv6.hlim", &decoded);
        assert!(field.is_some());
    }

    // --- Stream filter fields ---

    /// Helper: build a DecodedFrame from raw ethernet bytes with a stream ID.
    fn decoded_from_bytes_with_stream(bytes: &[u8], stream_id: Option<u32>) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
        DecodedFrame::new(frame, packet).with_stream_id(stream_id)
    }

    #[test]
    fn tcp_stream_field_returns_some_for_tcp_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            Some(5),
        );
        assert!(run_filter("tcp.stream == 5", &decoded));
    }

    #[test]
    fn tcp_stream_field_returns_none_for_udp_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin"),
            Some(3),
        );
        assert!(!run_filter("tcp.stream == 3", &decoded));
    }

    #[test]
    fn udp_stream_field_returns_some_for_udp_packet() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_udp.bin"),
            Some(3),
        );
        assert!(run_filter("udp.stream == 3", &decoded));
    }

    #[test]
    fn tcp_stream_bare_field_check() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            Some(0),
        );
        assert!(run_filter("tcp.stream", &decoded));
    }

    #[test]
    fn tcp_stream_without_tracking_returns_none() {
        let decoded = decoded_from_bytes_with_stream(
            include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin"),
            None,
        );
        assert!(!run_filter("tcp.stream == 0", &decoded));
    }

    // --- TLS filter tests ---

    #[test]
    fn has_protocol_tls_on_client_hello() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        assert!(run_filter("tls", &decoded));
    }

    #[test]
    fn tls_handshake_type_client_hello() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        assert!(run_filter("tls.handshake.type == 1", &decoded));
    }

    #[test]
    fn tls_handshake_type_server_hello() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_server_hello.bin"
        ));
        assert!(run_filter("tls.handshake.type == 2", &decoded));
    }

    #[test]
    fn tls_record_version_client_hello() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        // Record version is present and resolvable
        let field = resolve_field("tls.record_version", &decoded);
        assert!(field.is_some());
    }

    #[test]
    fn tls_client_version_is_0x0303() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        // 0x0303 == 771 decimal
        assert!(run_filter("tls.client_version == 771", &decoded));
    }

    #[test]
    fn tls_cipher_suite_server_hello() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_server_hello.bin"
        ));
        // cipher_suite = 0x1301 = 4865
        assert!(run_filter("tls.cipher_suite == 4865", &decoded));
    }

    // --- DNS filter tests ---

    #[test]
    fn dns_opcode_eq_zero() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.opcode == 0", &decoded));
    }

    #[test]
    fn dns_qcount_eq_1() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.qcount == 1", &decoded));
    }

    #[test]
    fn dns_acount_eq_0_for_query() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.acount == 0", &decoded));
    }

    #[test]
    fn dns_answer_bare_field_false_for_query() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        // Query has no answers, so dns.answer evaluates to false
        assert!(!run_filter("dns.answer", &decoded));
    }

    #[test]
    fn dns_answer_bare_field_true_for_response() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns_response.bin"
        ));
        // Response has answers, so dns.answer evaluates to true
        assert!(run_filter("dns.answer", &decoded));
    }

    // --- PortPair ordinal operator tests ---

    #[test]
    fn tcp_port_gt_1024_with_mixed_ports() {
        // TCP fixture: src=51514, dst=443
        // 51514 > 1024 is true, so the OR semantics should yield true
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.port > 1024", &decoded));
    }

    #[test]
    fn tcp_port_lt_1024_with_mixed_ports() {
        // TCP fixture: src=51514, dst=443
        // 443 < 1024 is true, so the OR semantics should yield true
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.port < 1024", &decoded));
    }

    #[test]
    fn tcp_port_gte_443() {
        // TCP fixture: src=51514, dst=443
        // Both >= 443, so true under both AND and OR
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.port >= 443", &decoded));
    }

    #[test]
    fn tcp_port_lte_443() {
        // TCP fixture: src=51514, dst=443
        // 443 <= 443 is true, so OR yields true
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter("tcp.port <= 443", &decoded));
    }

    // --- String filter tests ---

    #[test]
    fn dns_qname_contains_match() {
        // DNS fixture query_name = "example.com"
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter(r#"dns.qname contains "example""#, &decoded));
    }

    #[test]
    fn dns_qname_contains_no_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(!run_filter(r#"dns.qname contains "evil""#, &decoded));
    }

    #[test]
    fn dns_qname_contains_case_insensitive() {
        // "example.com" contains "EXAMPLE" (case-insensitive)
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter(r#"dns.qname contains "EXAMPLE""#, &decoded));
    }

    #[test]
    fn tls_sni_contains_match() {
        // TLS ClientHello fixture sni = "example.com"
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        assert!(run_filter(r#"tls.sni contains "example""#, &decoded));
    }

    #[test]
    fn tls_sni_contains_no_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        assert!(!run_filter(r#"tls.sni contains "evil""#, &decoded));
    }

    #[test]
    fn dns_qname_matches_regex() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter(r#"dns.qname matches "\.com$""#, &decoded));
    }

    #[test]
    fn dns_qname_matches_regex_no_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(!run_filter(r#"dns.qname matches "^evil""#, &decoded));
    }

    #[test]
    fn dns_qname_eq_exact_string() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter(r#"dns.qname == "example.com""#, &decoded));
    }

    #[test]
    fn dns_qname_eq_exact_string_no_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(!run_filter(r#"dns.qname == "google.com""#, &decoded));
    }

    #[test]
    fn dns_qname_neq_string() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter(r#"dns.qname != "google.com""#, &decoded));
    }

    #[test]
    fn ip_src_contains_address_substring() {
        // IPv4 fixture src=192.0.2.10
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter(r#"ip.src contains "192""#, &decoded));
    }

    #[test]
    fn ip_src_contains_no_match() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter(r#"ip.src contains "10.0""#, &decoded));
    }

    #[test]
    fn ip_src_matches_regex() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(run_filter(r#"ip.src matches "^192\.0\.2""#, &decoded));
    }

    #[test]
    fn dns_qname_bare_field_is_truthy_when_present() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_udp_dns.bin"
        ));
        assert!(run_filter("dns.qname", &decoded));
    }

    #[test]
    fn tls_sni_bare_field_is_truthy_when_present() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin"
        ));
        assert!(run_filter("tls.sni", &decoded));
    }

    // --- HTTP filter tests ---

    #[test]
    fn has_protocol_http_on_http_packet() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));
        assert!(run_filter("http", &decoded));
    }

    #[test]
    fn has_protocol_http_on_tcp_only_is_false() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp.bin"
        ));
        assert!(!run_filter("http", &decoded));
    }

    #[test]
    fn http_method_contains_get() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));
        assert!(run_filter(r#"http.method contains "GET""#, &decoded));
    }

    #[test]
    fn http_host_contains_example() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));
        assert!(run_filter(r#"http.host contains "example""#, &decoded));
    }

    #[test]
    fn http_uri_eq_root() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));
        assert!(run_filter(r#"http.uri == "/""#, &decoded));
    }

    #[test]
    fn http_content_type_contains_html() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));
        assert!(run_filter(r#"http.content_type contains "html""#, &decoded));
    }
}
