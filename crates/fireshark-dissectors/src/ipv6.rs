use std::net::Ipv6Addr;

use fireshark_core::{DecodeIssue, Ipv6Layer, Layer};

use crate::{DecodeError, NetworkPayload};

pub const ETHER_TYPE: u16 = 0x86dd;
const HEADER_LEN: usize = 40;

pub fn parse(bytes: &[u8], layer_offset: usize) -> Result<NetworkPayload<'_>, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv6",
            offset: layer_offset + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(DecodeError::Malformed("invalid IPv6 version"));
    }

    let traffic_class = ((bytes[0] & 0x0F) << 4) | (bytes[1] >> 4);
    let flow_label = u32::from_be_bytes([0, bytes[1] & 0x0F, bytes[2], bytes[3]]);
    let next_header = bytes[6];
    let hop_limit = bytes[7];
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let mut src = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    let source = Ipv6Addr::from(src);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&bytes[24..40]);
    let destination = Ipv6Addr::from(dst);
    let packet_len = HEADER_LEN + payload_len;
    let payload_end = packet_len.min(bytes.len());
    let mut issues = Vec::new();
    if bytes.len() < packet_len {
        issues.push(DecodeIssue::truncated(layer_offset + bytes.len()));
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv6(Ipv6Layer {
            source,
            destination,
            next_header,
            traffic_class,
            flow_label,
            hop_limit,
        }),
        protocol: next_header,
        payload: &bytes[HEADER_LEN..payload_end],
        payload_offset: layer_offset + HEADER_LEN,
        issues,
    })
}
