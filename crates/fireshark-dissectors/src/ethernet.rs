use fireshark_core::EthernetLayer;

use crate::DecodeError;

pub fn parse(bytes: &[u8]) -> Result<(EthernetLayer, &[u8]), DecodeError> {
    if bytes.len() < 14 {
        return Err(DecodeError::Truncated {
            layer: "Ethernet",
            offset: bytes.len(),
        });
    }

    let mut destination = [0_u8; 6];
    destination.copy_from_slice(&bytes[..6]);

    let mut source = [0_u8; 6];
    source.copy_from_slice(&bytes[6..12]);

    let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let layer = EthernetLayer {
        destination,
        source,
        ether_type,
    };

    Ok((layer, &bytes[14..]))
}
