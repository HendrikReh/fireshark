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
}
