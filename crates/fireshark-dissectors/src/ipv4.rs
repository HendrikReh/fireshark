use std::net::Ipv4Addr;

use fireshark_core::{Ipv4Layer, Layer};

use crate::DecodeError;

pub const ETHER_TYPE: u16 = 0x0800;
const MIN_HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8]) -> Result<Layer, DecodeError> {
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

    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let protocol = bytes[9];

    Ok(Layer::Ipv4(Ipv4Layer {
        source,
        destination,
        protocol,
    }))
}
