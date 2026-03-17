#[derive(Debug, thiserror::Error)]
pub enum TsharkError {
    #[error("failed to parse tshark version: {0}")]
    ParseVersion(String),
}
