use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    captured_len: usize,
    original_len: usize,
    timestamp: Option<Duration>,
    protocol: String,
    data: Vec<u8>,
}

impl Frame {
    pub fn builder() -> FrameBuilder {
        FrameBuilder {
            captured_len: 0,
            original_len: None,
            timestamp: None,
            protocol: String::from("UNKNOWN"),
            data: Vec::new(),
        }
    }

    pub fn captured_len(&self) -> usize {
        self.captured_len
    }

    pub fn original_len(&self) -> usize {
        self.original_len
    }

    pub fn timestamp(&self) -> Option<Duration> {
        self.timestamp
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
    original_len: Option<usize>,
    timestamp: Option<Duration>,
    protocol: String,
    data: Vec<u8>,
}

impl FrameBuilder {
    pub fn captured_len(mut self, captured_len: usize) -> Self {
        self.captured_len = captured_len;
        self
    }

    pub fn original_len(mut self, original_len: usize) -> Self {
        self.original_len = Some(original_len);
        self
    }

    pub fn timestamp(mut self, timestamp: Duration) -> Self {
        self.timestamp = Some(timestamp);
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
            original_len: self.original_len.unwrap_or(self.captured_len),
            timestamp: self.timestamp,
            protocol: self.protocol,
            data: self.data,
        }
    }
}
