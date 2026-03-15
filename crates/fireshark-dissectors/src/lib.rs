mod arp;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

pub use error::DecodeError;

use fireshark_core::{DecodeIssue, Layer, Packet};

pub(crate) struct NetworkPayload<'a> {
    pub(crate) layer: Layer,
    pub(crate) protocol: u8,
    pub(crate) payload: &'a [u8],
    pub(crate) payload_offset: usize,
    pub(crate) issues: Vec<DecodeIssue>,
}

pub fn decode_packet(bytes: &[u8]) -> Result<Packet, DecodeError> {
    let (ethernet, payload) = ethernet::parse(bytes)?;
    let ether_type = ethernet.ether_type;
    let mut layers = vec![Layer::Ethernet(ethernet)];
    let mut issues = Vec::new();

    match ether_type {
        arp::ETHER_TYPE => append_layer(arp::parse(payload), &mut layers, &mut issues),
        ipv4::ETHER_TYPE => append_network_layer(ipv4::parse(payload), &mut layers, &mut issues),
        ipv6::ETHER_TYPE => append_network_layer(ipv6::parse(payload), &mut layers, &mut issues),
        _ => {}
    }

    Ok(Packet::new(layers, issues))
}

fn append_layer(
    layer: Result<Layer, DecodeError>,
    layers: &mut Vec<Layer>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok(layer) => layers.push(layer),
        Err(DecodeError::Truncated { offset, .. }) => issues.push(DecodeIssue::truncated(offset)),
        Err(DecodeError::Malformed(_)) => {}
    }
}

fn append_network_layer(
    layer: Result<NetworkPayload<'_>, DecodeError>,
    layers: &mut Vec<Layer>,
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
            layers.push(layer);
            issues.extend(network_issues);
            if payload.is_empty() {
                return;
            }
            match protocol {
                tcp::IP_PROTOCOL => {
                    append_layer(tcp::parse(payload, payload_offset), layers, issues)
                }
                udp::IP_PROTOCOL => {
                    append_layer(udp::parse(payload, payload_offset), layers, issues)
                }
                icmp::IPV4_PROTOCOL | icmp::IPV6_PROTOCOL => {
                    append_layer(icmp::parse(payload, payload_offset), layers, issues)
                }
                _ => {}
            }
        }
        Err(error) => append_layer(Err(error), layers, issues),
    }
}
