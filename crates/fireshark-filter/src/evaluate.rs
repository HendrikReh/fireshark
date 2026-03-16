use std::net::{IpAddr, Ipv4Addr};

use fireshark_core::{DecodedFrame, Layer};

use crate::ast::{AddrValue, CmpOp, Expr, Protocol, ShorthandKind, Value};

/// A resolved field value from a decoded frame.
#[derive(Debug, Clone)]
enum FieldValue {
    Integer(u64),
    Address(IpAddr),
    Bool(bool),
    PortPair(u16, u16),
}

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

fn resolve_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    match field {
        "frame.len" => Some(FieldValue::Integer(decoded.frame().original_len() as u64)),
        "frame.cap_len" => Some(FieldValue::Integer(decoded.frame().captured_len() as u64)),
        _ => resolve_layer_field(field, decoded),
    }
}

fn resolve_layer_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
    for layer in decoded.packet().layers() {
        match (field, layer) {
            // IPv4
            ("ip.src", Layer::Ipv4(l)) => return Some(FieldValue::Address(IpAddr::V4(l.source))),
            ("ip.dst", Layer::Ipv4(l)) => {
                return Some(FieldValue::Address(IpAddr::V4(l.destination)));
            }
            ("ip.ttl", Layer::Ipv4(l)) => return Some(FieldValue::Integer(u64::from(l.ttl))),
            ("ip.id", Layer::Ipv4(l)) => {
                return Some(FieldValue::Integer(u64::from(l.identification)));
            }
            ("ip.proto", Layer::Ipv4(l)) => {
                return Some(FieldValue::Integer(u64::from(l.protocol)));
            }
            ("ip.dscp", Layer::Ipv4(l)) => return Some(FieldValue::Integer(u64::from(l.dscp))),
            ("ip.ecn", Layer::Ipv4(l)) => return Some(FieldValue::Integer(u64::from(l.ecn))),
            ("ip.checksum", Layer::Ipv4(l)) => {
                return Some(FieldValue::Integer(u64::from(l.header_checksum)));
            }
            ("ip.flags.df", Layer::Ipv4(l)) => return Some(FieldValue::Bool(l.dont_fragment)),
            ("ip.flags.mf", Layer::Ipv4(l)) => return Some(FieldValue::Bool(l.more_fragments)),
            ("ip.frag_offset", Layer::Ipv4(l)) => {
                return Some(FieldValue::Integer(u64::from(l.fragment_offset)));
            }

            // IPv6
            ("ip.src", Layer::Ipv6(l)) => return Some(FieldValue::Address(IpAddr::V6(l.source))),
            ("ip.dst", Layer::Ipv6(l)) => {
                return Some(FieldValue::Address(IpAddr::V6(l.destination)));
            }
            ("ipv6.hlim", Layer::Ipv6(l)) => {
                return Some(FieldValue::Integer(u64::from(l.hop_limit)));
            }
            ("ipv6.flow", Layer::Ipv6(l)) => {
                return Some(FieldValue::Integer(u64::from(l.flow_label)));
            }
            ("ipv6.tc", Layer::Ipv6(l)) => {
                return Some(FieldValue::Integer(u64::from(l.traffic_class)));
            }
            ("ipv6.nxt", Layer::Ipv6(l)) => {
                return Some(FieldValue::Integer(u64::from(l.next_header)));
            }

            // TCP
            ("tcp.srcport", Layer::Tcp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.source_port)));
            }
            ("tcp.dstport", Layer::Tcp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.destination_port)));
            }
            ("tcp.port", Layer::Tcp(l)) => {
                return Some(FieldValue::PortPair(l.source_port, l.destination_port));
            }
            ("tcp.seq", Layer::Tcp(l)) => return Some(FieldValue::Integer(u64::from(l.seq))),
            ("tcp.ack", Layer::Tcp(l)) => return Some(FieldValue::Integer(u64::from(l.ack))),
            ("tcp.window", Layer::Tcp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.window)));
            }
            ("tcp.hdr_len", Layer::Tcp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.data_offset) * 4));
            }
            ("tcp.flags.syn", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.syn)),
            ("tcp.flags.ack", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.ack)),
            ("tcp.flags.fin", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.fin)),
            ("tcp.flags.rst", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.rst)),
            ("tcp.flags.psh", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.psh)),
            ("tcp.flags.urg", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.urg)),
            ("tcp.flags.ece", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.ece)),
            ("tcp.flags.cwr", Layer::Tcp(l)) => return Some(FieldValue::Bool(l.flags.cwr)),

            // UDP
            ("udp.srcport", Layer::Udp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.source_port)));
            }
            ("udp.dstport", Layer::Udp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.destination_port)));
            }
            ("udp.port", Layer::Udp(l)) => {
                return Some(FieldValue::PortPair(l.source_port, l.destination_port));
            }
            ("udp.length", Layer::Udp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.length)));
            }

            // ICMP
            ("icmp.type", Layer::Icmp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.type_)));
            }
            ("icmp.code", Layer::Icmp(l)) => return Some(FieldValue::Integer(u64::from(l.code))),

            // ARP
            ("arp.opcode", Layer::Arp(l)) => {
                return Some(FieldValue::Integer(u64::from(l.operation)));
            }
            ("arp.spa", Layer::Arp(l)) => {
                return Some(FieldValue::Address(IpAddr::V4(l.sender_protocol_addr)));
            }
            ("arp.tpa", Layer::Arp(l)) => {
                return Some(FieldValue::Address(IpAddr::V4(l.target_protocol_addr)));
            }

            // Ethernet
            ("eth.type", Layer::Ethernet(l)) => {
                return Some(FieldValue::Integer(u64::from(l.ether_type)));
            }

            _ => {}
        }
    }
    None
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
            }
        }
        // Type mismatches
        _ => false,
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
        let frame = Frame::builder().data(bytes.to_vec()).build();
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
}
