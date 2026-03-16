//! Captured frame metadata and builder.

use std::time::Duration;

/// A single captured frame with its wire metadata and raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    captured_len: usize,
    original_len: usize,
    timestamp: Option<Duration>,
    protocol: String,
    data: Vec<u8>,
}

impl Frame {
    /// Create a new [`FrameBuilder`].
    pub fn builder() -> FrameBuilder {
        FrameBuilder {
            captured_len: None,
            original_len: None,
            timestamp: None,
            protocol: String::from("UNKNOWN"),
            data: Vec::new(),
        }
    }

    /// Number of bytes actually captured.
    pub fn captured_len(&self) -> usize {
        self.captured_len
    }

    /// Original on-wire length (may exceed `captured_len` for truncated captures).
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// Capture timestamp, if available.
    pub fn timestamp(&self) -> Option<Duration> {
        self.timestamp
    }

    /// Link-layer protocol name.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Raw frame bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Builder for constructing [`Frame`] instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameBuilder {
    captured_len: Option<usize>,
    original_len: Option<usize>,
    timestamp: Option<Duration>,
    protocol: String,
    data: Vec<u8>,
}

impl FrameBuilder {
    /// Set the captured byte count.
    pub fn captured_len(mut self, captured_len: usize) -> Self {
        self.captured_len = Some(captured_len);
        self
    }

    /// Set the original on-wire byte count.
    pub fn original_len(mut self, original_len: usize) -> Self {
        self.original_len = Some(original_len);
        self
    }

    /// Set the capture timestamp.
    pub fn timestamp(mut self, timestamp: Duration) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Set the link-layer protocol name.
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// Set the raw frame bytes.
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        self
    }

    /// Consume the builder and produce a [`Frame`].
    pub fn build(self) -> Frame {
        assert!(
            self.data.is_empty()
                || self
                    .captured_len
                    .is_none_or(|captured_len| captured_len == self.data.len()),
            "captured_len must match data length"
        );
        let captured_len = self.captured_len.unwrap_or(self.data.len());
        let original_len = self.original_len.unwrap_or(captured_len);
        assert!(
            original_len >= captured_len,
            "original_len must be >= captured_len"
        );
        Frame {
            captured_len,
            original_len,
            timestamp: self.timestamp,
            protocol: self.protocol,
            data: self.data,
        }
    }
}
