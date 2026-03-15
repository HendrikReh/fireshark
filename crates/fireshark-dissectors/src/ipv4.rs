use std::net::Ipv4Addr;

use fireshark_core::{DecodeIssue, Ipv4Layer, Layer};

use crate::{DecodeError, NetworkPayload};

pub const ETHER_TYPE: u16 = 0x0800;
const MIN_HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8]) -> Result<NetworkPayload<'_>, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: 14 + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if version != 4 {
        return Err(DecodeError::Malformed("invalid IPv4 version"));
    }
    if header_len < MIN_HEADER_LEN || bytes.len() < header_len {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: 14 + bytes.len(),
        });
    }

    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len {
        return Err(DecodeError::Malformed("invalid IPv4 total length"));
    }

    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let protocol = bytes[9];
    let fragment_bits = u16::from_be_bytes([bytes[6], bytes[7]]);
    let fragment_offset = fragment_bits & 0x1fff;
    let more_fragments = (fragment_bits & 0x2000) != 0;
    let payload_end = total_len.min(bytes.len());
    let mut issues = Vec::new();
    if bytes.len() < total_len {
        issues.push(DecodeIssue::truncated(14 + bytes.len()));
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv4(Ipv4Layer {
            source,
            destination,
            protocol,
            fragment_offset,
            more_fragments,
        }),
        protocol,
        payload: &bytes[header_len..payload_end],
        payload_offset: 14 + header_len,
        issues,
    })
}
