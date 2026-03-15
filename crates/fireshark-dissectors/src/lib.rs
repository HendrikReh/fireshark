mod arp;
mod error;
mod ethernet;
mod ipv4;
mod ipv6;
mod icmp;
mod tcp;
mod udp;

pub use error::DecodeError;

use fireshark_core::{DecodeIssue, Layer, Packet};

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
    layer: Result<(Layer, u8, &[u8]), DecodeError>,
    layers: &mut Vec<Layer>,
    issues: &mut Vec<DecodeIssue>,
) {
    match layer {
        Ok((layer, protocol, payload)) => {
            layers.push(layer);
            match protocol {
                tcp::IP_PROTOCOL => append_layer(tcp::parse(payload), layers, issues),
                udp::IP_PROTOCOL => append_layer(udp::parse(payload), layers, issues),
                icmp::IPV4_PROTOCOL | icmp::IPV6_PROTOCOL => append_layer(icmp::parse(payload), layers, issues),
                _ => {}
            }
        }
        Err(error) => append_layer(Err(error), layers, issues),
    }
}
