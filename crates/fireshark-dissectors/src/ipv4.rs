use std::net::Ipv4Addr;

use fireshark_core::{DecodeIssue, Ipv4Layer, Layer};

use crate::{DecodeError, NetworkPayload};

pub const ETHER_TYPE: u16 = 0x0800;
const MIN_HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8], layer_offset: usize) -> Result<NetworkPayload<'_>, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: layer_offset + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if version != 4 {
        return Err(DecodeError::Malformed("invalid IPv4 version"));
    }
    if header_len < MIN_HEADER_LEN {
        return Err(DecodeError::Malformed("invalid IPv4 header length"));
    }
    if bytes.len() < header_len {
        return Err(DecodeError::Truncated {
            layer: "IPv4",
            offset: layer_offset + bytes.len(),
        });
    }

    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len {
        return Err(DecodeError::Malformed("invalid IPv4 total length"));
    }

    let dscp = bytes[1] >> 2;
    let ecn = bytes[1] & 0x03;
    let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment_bits = u16::from_be_bytes([bytes[6], bytes[7]]);
    let dont_fragment = (fragment_bits & 0x4000) != 0;
    let more_fragments = (fragment_bits & 0x2000) != 0;
    let fragment_offset = fragment_bits & 0x1fff;
    let ttl = bytes[8];
    let protocol = bytes[9];
    let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let payload_end = total_len.min(bytes.len());
    let mut issues = Vec::new();
    if bytes.len() < total_len {
        issues.push(DecodeIssue::truncated(layer_offset + bytes.len()));
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv4(Ipv4Layer {
            source,
            destination,
            protocol,
            ttl,
            identification,
            dscp,
            ecn,
            dont_fragment,
            fragment_offset,
            more_fragments,
            header_checksum,
        }),
        protocol,
        payload: &bytes[header_len..payload_end],
        payload_offset: layer_offset + header_len,
        issues,
    })
}
