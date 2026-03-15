use fireshark_core::{Layer, TcpLayer};

use crate::DecodeError;

pub const IP_PROTOCOL: u8 = 6;
const HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8]) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "TCP",
            offset: 14 + bytes.len(),
        });
    }

    Ok(Layer::Tcp(TcpLayer {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
    }))
}
