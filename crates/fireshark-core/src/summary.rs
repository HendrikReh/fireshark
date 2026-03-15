use crate::Frame;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    pub protocol: String,
    pub length: usize,
}

impl From<&Frame> for PacketSummary {
    fn from(frame: &Frame) -> Self {
        Self {
            protocol: frame.protocol().to_string(),
            length: frame.captured_len(),
        }
    }
}
