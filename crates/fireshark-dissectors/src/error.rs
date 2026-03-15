use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("truncated {layer} header at byte offset {offset}")]
    Truncated { layer: &'static str, offset: usize },

    #[error("{0}")]
    Malformed(&'static str),
}
