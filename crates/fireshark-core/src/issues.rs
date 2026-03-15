#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeIssueKind {
    Truncated,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeIssue {
    kind: DecodeIssueKind,
    offset: usize,
}

impl DecodeIssue {
    pub fn truncated(offset: usize) -> Self {
        Self {
            kind: DecodeIssueKind::Truncated,
            offset,
        }
    }

    pub fn malformed(offset: usize) -> Self {
        Self {
            kind: DecodeIssueKind::Malformed,
            offset,
        }
    }

    pub fn kind(&self) -> &DecodeIssueKind {
        &self.kind
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}
