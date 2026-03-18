use std::net::Ipv4Addr;

use fireshark_core::{DecodeIssue, Ipv4Layer, Layer};

use crate::{DecodeError, NetworkPayload};

pub const ETHER_TYPE: u16 = 0x0800;
const MIN_HEADER_LEN: usize = 20;

/// Verify the IPv4 header checksum using the ones' complement algorithm.
///
/// Returns `true` when the checksum is valid (the ones' complement sum of all
/// 16-bit words in the header folds to `0xFFFF`).
fn verify_header_checksum(header: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

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

    // Validate the IPv4 header checksum. Skip when the field is zero, which
    // indicates the checksum was not computed (common with NIC offload).
    if header_checksum != 0 && !verify_header_checksum(&bytes[..header_len]) {
        issues.push(DecodeIssue::checksum_mismatch(layer_offset));
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
        is_non_initial_fragment: fragment_offset != 0,
    })
}
