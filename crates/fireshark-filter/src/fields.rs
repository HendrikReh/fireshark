use std::net::IpAddr;

use fireshark_core::{DecodedFrame, Layer};

/// A resolved field value from a decoded frame.
#[derive(Debug, Clone)]
pub(crate) enum FieldValue<'a> {
    Integer(u64),
    Address(IpAddr),
    Bool(bool),
    PortPair(u16, u16),
    Str(&'a str),
}

/// Resolve a named field to its value from a decoded frame.
///
/// Handles frame-level fields (`frame.len`, `frame.cap_len`), stream fields
/// (`tcp.stream`, `udp.stream`), and delegates per-layer fields to
/// [`resolve_layer_field`].
pub(crate) fn resolve_field<'a>(field: &str, decoded: &'a DecodedFrame) -> Option<FieldValue<'a>> {
    match field {
        "frame.len" => Some(FieldValue::Integer(decoded.frame().original_len() as u64)),
        "frame.cap_len" => Some(FieldValue::Integer(decoded.frame().captured_len() as u64)),
        "tcp.stream" => {
            if decoded
                .packet()
                .layers()
                .iter()
                .any(|l| matches!(l, Layer::Tcp(_)))
            {
                decoded
                    .stream_id()
                    .map(|id| FieldValue::Integer(u64::from(id)))
            } else {
                None
            }
        }
        "udp.stream" => {
            if decoded
                .packet()
                .layers()
                .iter()
                .any(|l| matches!(l, Layer::Udp(_)))
            {
                decoded
                    .stream_id()
                    .map(|id| FieldValue::Integer(u64::from(id)))
            } else {
                None
            }
        }
        _ => resolve_layer_field(field, decoded),
    }
}

fn resolve_layer_field<'a>(field: &str, decoded: &'a DecodedFrame) -> Option<FieldValue<'a>> {
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

            // DNS -- string fields
            ("dns.qname", Layer::Dns(l)) => {
                return l.query_name.as_deref().map(FieldValue::Str);
            }

            // DNS
            ("dns.id", Layer::Dns(l)) => {
                return Some(FieldValue::Integer(u64::from(l.transaction_id)));
            }
            ("dns.qr", Layer::Dns(l)) => return Some(FieldValue::Bool(l.is_response)),
            ("dns.opcode", Layer::Dns(l)) => {
                return Some(FieldValue::Integer(u64::from(l.opcode)));
            }
            ("dns.rcode", Layer::Dns(l)) => {
                return Some(FieldValue::Integer(u64::from(l.rcode)));
            }
            ("dns.qcount", Layer::Dns(l)) => {
                return Some(FieldValue::Integer(u64::from(l.question_count)));
            }
            ("dns.acount", Layer::Dns(l)) => {
                return Some(FieldValue::Integer(u64::from(l.answer_count)));
            }
            ("dns.qtype", Layer::Dns(l)) => {
                return l.query_type.map(|t| FieldValue::Integer(u64::from(t)));
            }
            ("dns.answer", Layer::Dns(l)) => {
                return Some(FieldValue::Bool(!l.answers.is_empty()));
            }

            // TLS -- string fields
            ("tls.sni", Layer::TlsClientHello(l)) => {
                return l.sni.as_deref().map(FieldValue::Str);
            }

            // TLS ClientHello
            ("tls.handshake.type", Layer::TlsClientHello(_)) => {
                return Some(FieldValue::Integer(1));
            }
            ("tls.record_version", Layer::TlsClientHello(l)) => {
                return Some(FieldValue::Integer(u64::from(l.record_version)));
            }
            ("tls.client_version", Layer::TlsClientHello(l)) => {
                return Some(FieldValue::Integer(u64::from(l.client_version)));
            }

            // TLS ServerHello
            ("tls.handshake.type", Layer::TlsServerHello(_)) => {
                return Some(FieldValue::Integer(2));
            }
            ("tls.record_version", Layer::TlsServerHello(l)) => {
                return Some(FieldValue::Integer(u64::from(l.record_version)));
            }
            ("tls.selected_version", Layer::TlsServerHello(l)) => {
                return l
                    .selected_version
                    .map(|v| FieldValue::Integer(u64::from(v)));
            }
            ("tls.cipher_suite", Layer::TlsServerHello(l)) => {
                return Some(FieldValue::Integer(u64::from(l.cipher_suite)));
            }

            // HTTP
            ("http.method", Layer::Http(l)) => {
                return l.method.as_deref().map(FieldValue::Str);
            }
            ("http.uri", Layer::Http(l)) => {
                return l.uri.as_deref().map(FieldValue::Str);
            }
            ("http.host", Layer::Http(l)) => {
                return l.host.as_deref().map(FieldValue::Str);
            }
            ("http.status_code", Layer::Http(l)) => {
                return l.status_code.map(|c| FieldValue::Integer(u64::from(c)));
            }
            ("http.content_type", Layer::Http(l)) => {
                return l.content_type.as_deref().map(FieldValue::Str);
            }

            _ => {}
        }
    }
    None
}

/// All recognized field names. Used by [`crate::validate_field_names`] to
/// detect typos in filter expressions.
pub(crate) const KNOWN_FIELDS: &[&str] = &[
    "frame.len",
    "frame.cap_len",
    "tcp.stream",
    "udp.stream",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.id",
    "ip.proto",
    "ip.dscp",
    "ip.ecn",
    "ip.checksum",
    "ip.flags.df",
    "ip.flags.mf",
    "ip.frag_offset",
    "ipv6.hlim",
    "ipv6.flow",
    "ipv6.tc",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.port",
    "tcp.seq",
    "tcp.ack",
    "tcp.window",
    "tcp.hdr_len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.rst",
    "tcp.flags.psh",
    "tcp.flags.urg",
    "tcp.flags.ece",
    "tcp.flags.cwr",
    "udp.srcport",
    "udp.dstport",
    "udp.port",
    "udp.length",
    "icmp.type",
    "icmp.code",
    "arp.opcode",
    "arp.spa",
    "arp.tpa",
    "eth.type",
    "dns.qname",
    "dns.id",
    "dns.qr",
    "dns.opcode",
    "dns.rcode",
    "dns.qcount",
    "dns.acount",
    "dns.qtype",
    "dns.answer",
    "tls.sni",
    "tls.handshake.type",
    "tls.record_version",
    "tls.client_version",
    "tls.selected_version",
    "tls.cipher_suite",
    "http.method",
    "http.uri",
    "http.host",
    "http.status_code",
    "http.content_type",
];

#[cfg(test)]
mod tests {
    use super::*;
    use fireshark_core::{Frame, Layer};
    use fireshark_dissectors::decode_packet;

    fn decoded_from_bytes(bytes: &[u8]) -> DecodedFrame {
        let packet = decode_packet(bytes).unwrap();
        let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
        DecodedFrame::new(frame, packet)
    }

    #[test]
    fn http_host_field_borrows_underlying_packet_string() {
        let decoded = decoded_from_bytes(include_bytes!(
            "../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin"
        ));

        let expected = decoded
            .packet()
            .layers()
            .iter()
            .find_map(|layer| match layer {
                Layer::Http(http) => http.host.as_deref(),
                _ => None,
            })
            .expect("http host should be present");

        let resolved = match resolve_field("http.host", &decoded) {
            Some(FieldValue::Str(value)) => value,
            other => panic!("unexpected resolved field: {other:?}"),
        };

        assert_eq!(resolved, expected);
        assert_eq!(resolved.as_ptr(), expected.as_ptr());
    }
}
