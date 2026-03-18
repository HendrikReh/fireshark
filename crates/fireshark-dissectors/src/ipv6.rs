use std::net::Ipv6Addr;

use fireshark_core::{DecodeIssue, Ipv6Layer, Layer};

use crate::{DecodeError, NetworkPayload};

pub const ETHER_TYPE: u16 = 0x86dd;
const HEADER_LEN: usize = 40;

/// IPv6 extension headers whose format allows skipping to the next header.
///
/// ESP (50) and AH (51) are NOT included:
/// - ESP payload is encrypted; next_header is only in the encrypted trailer.
/// - AH uses a different length formula: `(hdr_ext_len + 2) * 4`, not the
///   standard `(hdr_ext_len + 1) * 8`. Since fireshark does not decode IPsec,
///   encountering ESP or AH stops the extension header walk.
fn is_skippable_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        0  |  // Hop-by-Hop Options
        43 |  // Routing
        44 |  // Fragment
        60 // Destination Options
    )
}

/// Maximum number of extension headers to skip (prevents infinite loops
/// on malformed packets).
const MAX_EXT_HEADERS: usize = 16;

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
    let mut next_header = bytes[6];
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

    // Walk the extension header chain to find the real transport protocol.
    // Each generic extension header has: next_header (1 byte) + hdr_ext_len (1 byte)
    // where the total length is (hdr_ext_len + 1) * 8 bytes.
    // Fragment headers are a special case: always 8 bytes.
    let mut ext_offset = HEADER_LEN;
    let mut is_non_initial_fragment = false;

    for _ in 0..MAX_EXT_HEADERS {
        if !is_skippable_extension(next_header) {
            break;
        }
        // Need at least 2 bytes for next_header + hdr_ext_len (or fragment fields)
        if ext_offset + 2 > payload_end {
            break;
        }
        let ext_next = bytes[ext_offset];

        if next_header == 44 {
            // Fragment header: fixed 8 bytes
            // Byte layout: next_header(1) + reserved(1) + frag_offset_flags(2) + identification(4)
            if ext_offset + 8 > payload_end {
                break;
            }
            let frag_offset_flags =
                u16::from_be_bytes([bytes[ext_offset + 2], bytes[ext_offset + 3]]);
            let fragment_offset = frag_offset_flags >> 3;
            if fragment_offset != 0 {
                is_non_initial_fragment = true;
            }
            next_header = ext_next;
            ext_offset += 8;
        } else {
            // Generic extension header: (hdr_ext_len + 1) * 8
            let ext_len = (usize::from(bytes[ext_offset + 1]) + 1) * 8;
            if ext_offset + ext_len > payload_end {
                break;
            }
            next_header = ext_next;
            ext_offset += ext_len;
        }
    }

    Ok(NetworkPayload {
        layer: Layer::Ipv6(Ipv6Layer {
            source,
            destination,
            next_header: bytes[6], // Store the original next_header in the layer
            traffic_class,
            flow_label,
            hop_limit,
        }),
        protocol: next_header, // Use the resolved protocol for transport dispatch
        payload: &bytes[ext_offset..payload_end],
        payload_offset: layer_offset + ext_offset,
        issues,
        is_non_initial_fragment,
    })
}
