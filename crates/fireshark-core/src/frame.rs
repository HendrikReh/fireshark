#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    captured_len: usize,
    protocol: String,
    data: Vec<u8>,
}

impl Frame {
    pub fn builder() -> FrameBuilder {
        FrameBuilder {
            captured_len: 0,
            protocol: String::from("UNKNOWN"),
            data: Vec::new(),
        }
    }

    pub fn captured_len(&self) -> usize {
        self.captured_len
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameBuilder {
    captured_len: usize,
    protocol: String,
    data: Vec<u8>,
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

    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        if self.captured_len == 0 {
            self.captured_len = self.data.len();
        }
        self
    }

    pub fn build(self) -> Frame {
        Frame {
            captured_len: self.captured_len,
            protocol: self.protocol,
            data: self.data,
        }
    }
}
