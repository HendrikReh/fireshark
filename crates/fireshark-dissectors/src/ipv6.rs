use std::net::Ipv6Addr;

use fireshark_core::{Ipv6Layer, Layer};

use crate::DecodeError;

pub const ETHER_TYPE: u16 = 0x86dd;
const HEADER_LEN: usize = 40;

pub fn parse(bytes: &[u8]) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "IPv6",
            offset: 14 + bytes.len(),
        });
    }

    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(DecodeError::Malformed("invalid IPv6 version"));
    }

    let next_header = bytes[6];
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("valid IPv6 source slice"));
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).expect("valid IPv6 destination slice"));

    Ok(Layer::Ipv6(Ipv6Layer {
        source,
        destination,
        next_header,
    }))
}
