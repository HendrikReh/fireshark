#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeIssueKind {
    Truncated,
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

    pub fn kind(&self) -> &DecodeIssueKind {
        &self.kind
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}
