#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    captured_len: usize,
    protocol: String,
}

impl Frame {
    pub fn builder() -> FrameBuilder {
        FrameBuilder {
            captured_len: 0,
            protocol: String::from("UNKNOWN"),
        }
    }

    pub fn captured_len(&self) -> usize {
        self.captured_len
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameBuilder {
    captured_len: usize,
    protocol: String,
}

impl FrameBuilder {
    pub fn captured_len(mut self, captured_len: usize) -> Self {
        self.captured_len = captured_len;
        self
    }

    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    pub fn build(self) -> Frame {
        Frame {
            captured_len: self.captured_len,
            protocol: self.protocol,
        }
    }
}
