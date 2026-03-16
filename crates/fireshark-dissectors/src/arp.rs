use std::net::Ipv4Addr;

use fireshark_core::{ArpLayer, Layer};

use crate::DecodeError;

pub const ETHER_TYPE: u16 = 0x0806;
pub const HEADER_LEN: usize = 28;

pub fn parse(bytes: &[u8], layer_offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "ARP",
            offset: layer_offset + bytes.len(),
        });
    }

    let hardware_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let protocol_type = u16::from_be_bytes([bytes[2], bytes[3]]);
    let hardware_len = bytes[4];
    let protocol_len = bytes[5];

    if hardware_type != 1 || protocol_type != 0x0800 || hardware_len != 6 || protocol_len != 4 {
        return Err(DecodeError::Malformed("unsupported ARP header"));
    }

    let operation = u16::from_be_bytes([bytes[6], bytes[7]]);
    let sender_protocol_addr = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
    let target_protocol_addr = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);

    Ok(Layer::Arp(ArpLayer {
        operation,
        sender_protocol_addr,
        target_protocol_addr,
    }))
}
