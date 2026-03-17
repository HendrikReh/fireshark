#[derive(Debug, thiserror::Error)]
pub enum TsharkError {
    #[error("tshark not found: {0}")]
    NotFound(String),
    #[error("failed to parse tshark version: {0}")]
    ParseVersion(String),
    #[error("unsupported tshark version {version} (minimum: 3.0.0)")]
    UnsupportedVersion { version: String },
    #[error("tshark execution failed: {0}")]
    Execution(String),
    #[error("failed to parse tshark output: {0}")]
    ParseOutput(String),
}
