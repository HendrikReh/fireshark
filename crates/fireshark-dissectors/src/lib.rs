mod arp;
mod error;
mod ethernet;
mod ipv4;
mod ipv6;

pub use error::DecodeError;

use fireshark_core::{DecodeIssue, Layer, Packet};

pub fn decode_packet(bytes: &[u8]) -> Result<Packet, DecodeError> {
    let (ethernet, payload) = ethernet::parse(bytes)?;
    let mut layers = vec![Layer::Ethernet(ethernet.clone())];
    let mut issues = Vec::new();

    match ethernet.ether_type {
        arp::ETHER_TYPE => append_layer(arp::parse(payload), &mut layers, &mut issues),
        ipv4::ETHER_TYPE => append_layer(ipv4::parse(payload), &mut layers, &mut issues),
        ipv6::ETHER_TYPE => append_layer(ipv6::parse(payload), &mut layers, &mut issues),
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
