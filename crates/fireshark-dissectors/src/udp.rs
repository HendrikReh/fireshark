use fireshark_core::{Layer, UdpLayer};

use crate::DecodeError;

pub const IP_PROTOCOL: u8 = 17;
const HEADER_LEN: usize = 8;

pub fn parse(bytes: &[u8]) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "UDP",
            offset: 14 + bytes.len(),
        });
    }

    Ok(Layer::Udp(UdpLayer {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
    }))
}
