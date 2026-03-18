use std::net::IpAddr;

use fireshark_core::{DecodedFrame, Layer};

/// A resolved field value from a decoded frame.
#[derive(Debug, Clone)]
pub(crate) enum FieldValue {
    Integer(u64),
    Address(IpAddr),
    Bool(bool),
    PortPair(u16, u16),
    Str(String),
}

/// Resolve a named field to its value from a decoded frame.
///
/// Handles frame-level fields (`frame.len`, `frame.cap_len`), stream fields
/// (`tcp.stream`, `udp.stream`), and delegates per-layer fields to
/// [`resolve_layer_field`].
pub(crate) fn resolve_field(field: &str, decoded: &DecodedFrame) -> Option<FieldValue> {
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

            // DNS -- string fields
            ("dns.qname", Layer::Dns(l)) => {
                return l.query_name.as_ref().map(|n| FieldValue::Str(n.clone()));
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
                return l.sni.as_ref().map(|s| FieldValue::Str(s.clone()));
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
                return l.method.as_ref().map(|s| FieldValue::Str(s.clone()));
            }
            ("http.uri", Layer::Http(l)) => {
                return l.uri.as_ref().map(|s| FieldValue::Str(s.clone()));
            }
            ("http.host", Layer::Http(l)) => {
                return l.host.as_ref().map(|s| FieldValue::Str(s.clone()));
            }
            ("http.status_code", Layer::Http(l)) => {
                return l.status_code.map(|c| FieldValue::Integer(u64::from(c)));
            }
            ("http.content_type", Layer::Http(l)) => {
                return l.content_type.as_ref().map(|s| FieldValue::Str(s.clone()));
            }

            _ => {}
        }
    }
    None
}
