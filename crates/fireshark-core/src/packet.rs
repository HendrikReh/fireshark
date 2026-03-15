use crate::{DecodeIssue, Layer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    layers: Vec<Layer>,
    issues: Vec<DecodeIssue>,
}

impl Packet {
    pub fn new(layers: Vec<Layer>, issues: Vec<DecodeIssue>) -> Self {
        Self { layers, issues }
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    pub fn issues(&self) -> &[DecodeIssue] {
        &self.issues
    }

    pub fn layer_names(&self) -> Vec<&'static str> {
        self.layers.iter().map(Layer::name).collect()
    }

    pub fn transport_ports(&self) -> Option<(u16, u16)> {
        self.layers.iter().find_map(|layer| match layer {
            Layer::Tcp(layer) => Some((layer.source_port, layer.destination_port)),
            Layer::Udp(layer) => Some((layer.source_port, layer.destination_port)),
            _ => None,
        })
    }
}
