//! Protocol dissectors for Ethernet-framed packet decoding.
//!
//! The main entry point is [`decode_packet`], which chains dissectors from
//! Ethernet through network (IPv4/IPv6/ARP) to transport (TCP/UDP/ICMP) layers.
//! Each dissector validates its header, extracts typed fields, and reports
//! decode issues (truncation, malformation) rather than panicking.

mod arp;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

pub use error::DecodeError;

use fireshark_core::{DecodeIssue, Layer, LayerSpan, Packet};

/// Internal result from network-layer dissectors (IPv4, IPv6).
///
/// Carries the decoded layer, the transport protocol number, a payload
/// slice for the next dissector, and the absolute byte offset from
/// frame start where the payload begins. The `issues` vec collects
/// soft warnings (e.g., truncation detected from declared vs actual length).
pub(crate) struct NetworkPayload<'a> {
    /// The decoded network layer (e.g., `Layer::Ipv4`, `Layer::Ipv6`).
    pub(crate) layer: Layer,
    /// Transport protocol number: IPv4 `Protocol` field or IPv6 `Next Header`.
    pub(crate) protocol: u8,
    /// Payload bytes after the network header, up to the declared packet length.
    pub(crate) payload: &'a [u8],
    /// Absolute byte offset from frame start where `payload` begins.
    /// Used for transport-layer truncation error offsets and `LayerSpan` computation.
    pub(crate) payload_offset: usize,
    /// Soft decode issues (e.g., declared length exceeds captured bytes).
    pub(crate) issues: Vec<DecodeIssue>,
}

pub fn decode_packet(bytes: &[u8]) -> Result<Packet, DecodeError> {
    let (ethernet, payload) = ethernet::parse(bytes)?;
    let ether_type = ethernet.ether_type;
    let mut layers = vec![Layer::Ethernet(ethernet)];
    let mut spans = vec![LayerSpan {
        offset: 0,
        len: ethernet::HEADER_LEN,
    }];
    let mut issues = Vec::new();

    match ether_type {
        arp::ETHER_TYPE => {
            append_layer_with_span(
                arp::parse(payload, ethernet::HEADER_LEN),
                ethernet::HEADER_LEN,
                LayerSpan {
                    offset: ethernet::HEADER_LEN,
                    len: arp::HEADER_LEN,
                },
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        ipv4::ETHER_TYPE => {
            append_network_layer(
                ipv4::parse(payload, ethernet::HEADER_LEN),
                ethernet::HEADER_LEN,
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        ipv6::ETHER_TYPE => {
            append_network_layer(
                ipv6::parse(payload, ethernet::HEADER_LEN),
                ethernet::HEADER_LEN,
                &mut layers,
                &mut spans,
                &mut issues,
            );
        }
        _ => {}
    }

    Ok(Packet::with_spans(layers, issues, spans))
}

fn append_layer_with_span(
    layer: Result<Layer, DecodeError>,
    layer_offset: usize,
    span: LayerSpan,
    layers: &mut Vec<Layer>,
    spans: &mut Vec<LayerSpan>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok(layer) => {
            layers.push(layer);
            spans.push(span);
        }
        Err(DecodeError::Truncated { offset, .. }) => issues.push(DecodeIssue::truncated(offset)),
        Err(DecodeError::Malformed(_)) => issues.push(DecodeIssue::malformed(layer_offset)),
    }
}

fn transport_span(layer: &Layer, payload_offset: usize) -> LayerSpan {
    let len = match layer {
        Layer::Tcp(tcp) => usize::from(tcp.data_offset) * 4,
        Layer::Udp(_) => 8,
        // `detail.is_some()` means 8 bytes were available and consumed (type + code +
        // checksum + rest-of-header). `None` means only the 4-byte minimum (type + code +
        // checksum) was present. This correctly represents consumed bytes even for
        // unrecognized ICMP types, because `IcmpDetail::Other` is still `Some`.
        Layer::Icmp(icmp) => {
            if icmp.detail.is_some() {
                8
            } else {
                4
            }
        }
        _ => unreachable!("transport_span called with non-transport layer"),
    };
    LayerSpan {
        offset: payload_offset,
        len,
    }
}

fn append_network_layer(
    layer: Result<NetworkPayload<'_>, DecodeError>,
    layer_offset: usize,
    layers: &mut Vec<Layer>,
    spans: &mut Vec<LayerSpan>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok(NetworkPayload {
            layer,
            protocol,
            payload,
            payload_offset,
            issues: network_issues,
        }) => {
            let network_span = LayerSpan {
                offset: layer_offset,
                len: payload_offset - layer_offset,
            };
            let transport_header_available = match &layer {
                Layer::Ipv4(layer) => layer.fragment_offset == 0,
                _ => true,
            };
            layers.push(layer);
            spans.push(network_span);
            issues.extend(network_issues);
            if payload.is_empty() || !transport_header_available {
                return;
            }
            let parse_transport =
                |result: Result<Layer, DecodeError>,
                 layers: &mut Vec<Layer>,
                 spans: &mut Vec<LayerSpan>,
                 issues: &mut Vec<DecodeIssue>| {
                    let span = match &result {
                        Ok(layer) => transport_span(layer, payload_offset),
                        Err(_) => LayerSpan {
                            offset: payload_offset,
                            len: 0,
                        },
                    };
                    append_layer_with_span(result, payload_offset, span, layers, spans, issues);
                };
            match protocol {
                tcp::IP_PROTOCOL => {
                    parse_transport(tcp::parse(payload, payload_offset), layers, spans, issues);
                }
                udp::IP_PROTOCOL => {
                    parse_transport(udp::parse(payload, payload_offset), layers, spans, issues);
                }
                icmp::IPV4_PROTOCOL | icmp::IPV6_PROTOCOL => {
                    parse_transport(icmp::parse(payload, payload_offset), layers, spans, issues);
                }
                _ => {}
            }
        }
        Err(error) => {
            append_layer_with_span(
                Err(error),
                layer_offset,
                LayerSpan {
                    offset: layer_offset,
                    len: 0,
                },
                layers,
                spans,
                issues,
            );
        }
    }
}
