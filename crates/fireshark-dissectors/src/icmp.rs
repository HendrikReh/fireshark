use fireshark_core::{IcmpDetail, IcmpLayer, Layer};

use crate::DecodeError;

pub const IPV4_PROTOCOL: u8 = 1;
pub const IPV6_PROTOCOL: u8 = 58;
const MIN_HEADER_LEN: usize = 4;
const DETAIL_LEN: usize = 8;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "ICMP",
            offset: offset + bytes.len(),
        });
    }

    let type_ = bytes[0];
    let code = bytes[1];

    let detail = if bytes.len() >= DETAIL_LEN {
        Some(parse_detail(type_, bytes))
    } else {
        None
    };

    Ok(Layer::Icmp(IcmpLayer {
        type_,
        code,
        detail,
    }))
}

fn parse_detail(type_: u8, bytes: &[u8]) -> IcmpDetail {
    let word_hi = u16::from_be_bytes([bytes[4], bytes[5]]);
    let word_lo = u16::from_be_bytes([bytes[6], bytes[7]]);

    match type_ {
        0 => IcmpDetail::EchoReply {
            identifier: word_hi,
            sequence: word_lo,
        },
        3 => IcmpDetail::DestinationUnreachable {
            next_hop_mtu: word_lo,
        },
        8 => IcmpDetail::EchoRequest {
            identifier: word_hi,
            sequence: word_lo,
        },
        _ => IcmpDetail::Other {
            rest_of_header: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        },
    }
}
