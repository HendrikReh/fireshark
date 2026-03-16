use std::time::Duration;

use crate::Frame;
use crate::{Layer, Packet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    pub protocol: String,
    pub length: usize,
    pub source: String,
    pub destination: String,
    pub timestamp: Option<Duration>,
}

impl From<&Frame> for PacketSummary {
    fn from(frame: &Frame) -> Self {
        Self {
            protocol: frame.protocol().to_string(),
            length: frame.captured_len(),
            source: String::new(),
            destination: String::new(),
            timestamp: frame.timestamp(),
        }
    }
}

impl PacketSummary {
    pub fn from_packet(packet: &Packet, frame: &Frame) -> Self {
        let protocol = packet
            .layers()
            .iter()
            .rev()
            .find(|layer| !matches!(layer, Layer::Ethernet(_)))
            .map(Layer::name)
            .unwrap_or("Unknown")
            .to_string();

        let (source, destination) = format_endpoints(packet);

        Self {
            protocol,
            length: frame.captured_len(),
            source,
            destination,
            timestamp: frame.timestamp(),
        }
    }
}

fn format_endpoints(packet: &Packet) -> (String, String) {
    let ports = packet.transport_ports();
    for layer in packet.layers() {
        match layer {
            Layer::Ipv4(layer) => {
                return (
                    append_port(layer.source.to_string(), ports.map(|ports| ports.0)),
                    append_port(layer.destination.to_string(), ports.map(|ports| ports.1)),
                );
            }
            Layer::Ipv6(layer) => {
                return (
                    append_port(layer.source.to_string(), ports.map(|ports| ports.0)),
                    append_port(layer.destination.to_string(), ports.map(|ports| ports.1)),
                );
            }
            _ => {}
        }
    }

    (String::new(), String::new())
}

fn append_port(address: String, port: Option<u16>) -> String {
    match port {
        Some(port) if address.contains(':') => format!("[{address}]:{port}"),
        Some(port) => format!("{address}:{port}"),
        None => address,
    }
}
