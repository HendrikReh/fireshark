//! Protocol dissectors for Ethernet-framed packet decoding.
//!
//! The main entry point is [`decode_packet`], which chains dissectors from
//! Ethernet through network (IPv4/IPv6/ARP) to transport (TCP/UDP/ICMP) layers.
//! Each dissector validates its header, extracts typed fields, and reports
//! decode issues (truncation, malformation) rather than panicking.

mod arp;
mod dns;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
pub mod tls;
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

            // Application-layer dispatch: attempt to decode protocols above transport.
            // Extract port info and span details before the mutable borrow.
            let app_dispatch_info = layers.last().and_then(|last_transport| {
                let (src_port, dst_port, hdr_len, is_tcp) = match last_transport {
                    Layer::Udp(udp) => (
                        udp.source_port,
                        udp.destination_port,
                        udp::HEADER_LEN,
                        false,
                    ),
                    Layer::Tcp(tcp) => (
                        tcp.source_port,
                        tcp.destination_port,
                        usize::from(tcp.data_offset) * 4,
                        true,
                    ),
                    _ => return None,
                };
                let last_span = spans.last()?;
                let transport_end = last_span.offset + last_span.len;
                let app_payload_start = transport_end.saturating_sub(payload_offset);
                let app_payload_len = if is_tcp {
                    payload.len().saturating_sub(app_payload_start)
                } else {
                    // For UDP, respect the declared length field
                    let declared = match last_transport {
                        Layer::Udp(udp) => usize::from(udp.length).saturating_sub(hdr_len),
                        _ => 0,
                    };
                    declared.min(payload.len().saturating_sub(app_payload_start))
                };
                let app_payload_end = app_payload_start + app_payload_len;
                if transport_end > payload_offset
                    && app_payload_start <= app_payload_end
                    && app_payload_end <= payload.len()
                {
                    Some((src_port, dst_port, transport_end, app_payload_end, is_tcp))
                } else {
                    None
                }
            });
            if let Some((src_port, dst_port, transport_end, app_payload_end, is_tcp)) =
                app_dispatch_info
            {
                let app_payload = &payload[transport_end - payload_offset..app_payload_end];
                if !app_payload.is_empty() {
                    if !is_tcp && (src_port == dns::UDP_PORT || dst_port == dns::UDP_PORT) {
                        let span = LayerSpan {
                            offset: transport_end,
                            len: app_payload.len(),
                        };
                        append_layer_with_span(
                            dns::parse(app_payload, transport_end),
                            transport_end,
                            span,
                            layers,
                            spans,
                            issues,
                        );
                    } else if is_tcp
                        && app_payload.len() >= 9
                        && app_payload[0] == 0x16
                        && app_payload[1] == 0x03
                        && app_payload[2] <= 0x03
                        && (app_payload[5] == 0x01 || app_payload[5] == 0x02)
                    {
                        let span = LayerSpan {
                            offset: transport_end,
                            len: app_payload.len(),
                        };
                        append_layer_with_span(
                            tls::parse(app_payload, transport_end),
                            transport_end,
                            span,
                            layers,
                            spans,
                            issues,
                        );
                    }
                }
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
