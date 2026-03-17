use crate::TsharkError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsharkVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

pub fn parse_version_output(output: &str) -> Result<TsharkVersion, TsharkError> {
    let token = output
        .split_whitespace()
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .ok_or_else(|| TsharkError::ParseVersion(output.to_string()))?;

    let mut parts = token.trim_end_matches('.').split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TsharkError::ParseVersion(output.to_string()))?;
    let minor = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TsharkError::ParseVersion(output.to_string()))?;
    let patch = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TsharkError::ParseVersion(output.to_string()))?;

    Ok(TsharkVersion {
        major,
        minor,
        patch,
    })
}
