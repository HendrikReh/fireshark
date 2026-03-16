//! Decoded packet model holding protocol layers, decode issues, and byte spans.

use crate::{DecodeIssue, Layer};

/// Byte range of a single protocol layer within the raw frame data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerSpan {
    pub offset: usize,
    pub len: usize,
}

/// A fully decoded packet composed of protocol layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    layers: Vec<Layer>,
    issues: Vec<DecodeIssue>,
    spans: Vec<LayerSpan>,
}

impl Packet {
    /// Create a packet without layer byte spans.
    pub fn new(layers: Vec<Layer>, issues: Vec<DecodeIssue>) -> Self {
        Self::with_spans(layers, issues, Vec::new())
    }

    /// Create a packet with layer byte spans.
    ///
    /// `spans` must have the same length as `layers` — `spans[i]` describes
    /// the byte range of `layers[i]` within the raw frame data. Pass an empty
    /// `Vec` if spans are not available.
    pub fn with_spans(layers: Vec<Layer>, issues: Vec<DecodeIssue>, spans: Vec<LayerSpan>) -> Self {
        debug_assert!(
            spans.is_empty() || spans.len() == layers.len(),
            "spans must be empty or match layers length"
        );
        Self {
            layers,
            issues,
            spans,
        }
    }

    /// Protocol layers in parse order.
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// Issues encountered during decoding.
    pub fn issues(&self) -> &[DecodeIssue] {
        &self.issues
    }

    /// Byte spans for each layer, if available.
    pub fn spans(&self) -> &[LayerSpan] {
        &self.spans
    }

    /// Shorthand: names of all layers in order.
    pub fn layer_names(&self) -> Vec<&'static str> {
        self.layers.iter().map(Layer::name).collect()
    }

    /// Extract (source_port, destination_port) from the first transport layer.
    pub fn transport_ports(&self) -> Option<(u16, u16)> {
        self.layers.iter().find_map(|layer| match layer {
            Layer::Tcp(layer) => Some((layer.source_port, layer.destination_port)),
            Layer::Udp(layer) => Some((layer.source_port, layer.destination_port)),
            _ => None,
        })
    }
}
