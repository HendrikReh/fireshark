//! Decode issues reported during protocol dissection.

/// Classification of a decode issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeIssueKind {
    /// The input was shorter than required.
    Truncated,
    /// A field contained an invalid or unexpected value.
    Malformed,
}

/// A problem encountered while decoding a packet at a specific byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeIssue {
    kind: DecodeIssueKind,
    offset: usize,
}

impl DecodeIssue {
    /// Create a truncation issue at `offset`.
    pub fn truncated(offset: usize) -> Self {
        Self {
            kind: DecodeIssueKind::Truncated,
            offset,
        }
    }

    /// Create a malformation issue at `offset`.
    pub fn malformed(offset: usize) -> Self {
        Self {
            kind: DecodeIssueKind::Malformed,
            offset,
        }
    }

    /// The kind of issue.
    pub fn kind(&self) -> &DecodeIssueKind {
        &self.kind
    }

    /// Byte offset within the frame where the issue was detected.
    pub fn offset(&self) -> usize {
        self.offset
    }
}
