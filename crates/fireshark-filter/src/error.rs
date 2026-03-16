/// Error returned by the filter parser or lexer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("filter error: {message} at position {position}")]
pub struct FilterError {
    pub message: String,
    pub position: usize,
}

impl FilterError {
    pub fn new(message: impl Into<String>, position: usize) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}
