use fireshark_core::{Layer, TcpFlags, TcpLayer};

use crate::DecodeError;

pub const IP_PROTOCOL: u8 = 6;
const MIN_HEADER_LEN: usize = 20;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "TCP",
            offset: offset + bytes.len(),
        });
    }

    let data_offset = bytes[12] >> 4;
    if data_offset < 5 {
        return Err(DecodeError::Malformed("invalid TCP data offset"));
    }
    let header_len = usize::from(data_offset) * 4;
    if bytes.len() < header_len {
        return Err(DecodeError::Truncated {
            layer: "TCP",
            offset: offset + bytes.len(),
        });
    }

    let flag_bits = bytes[13];
    let flags = TcpFlags {
        fin: (flag_bits & 0x01) != 0,
        syn: (flag_bits & 0x02) != 0,
        rst: (flag_bits & 0x04) != 0,
        psh: (flag_bits & 0x08) != 0,
        ack: (flag_bits & 0x10) != 0,
        urg: (flag_bits & 0x20) != 0,
        ece: (flag_bits & 0x40) != 0,
        cwr: (flag_bits & 0x80) != 0,
    };

    Ok(Layer::Tcp(TcpLayer {
        source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        data_offset,
        flags,
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
    }))
}
