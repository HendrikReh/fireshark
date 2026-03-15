use fireshark_core::{IcmpLayer, Layer};

use crate::DecodeError;

pub const IPV4_PROTOCOL: u8 = 1;
pub const IPV6_PROTOCOL: u8 = 58;
const HEADER_LEN: usize = 4;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "ICMP",
            offset: offset + bytes.len(),
        });
    }

    Ok(Layer::Icmp(IcmpLayer {
        type_: bytes[0],
        code: bytes[1],
    }))
}
