use std::fmt;
use std::path::PathBuf;
use std::process::Command;

use crate::TsharkError;

/// Minimum supported tshark version (JSON output format stabilized).
const MIN_MAJOR: u32 = 3;
const MIN_MINOR: u32 = 0;
const MIN_PATCH: u32 = 0;

/// Known filesystem locations where tshark may be installed.
const KNOWN_PATHS: &[&str] = &[
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsharkVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for TsharkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl TsharkVersion {
    /// Returns `true` if this version meets the minimum requirement (3.0.0).
    pub fn is_supported(&self) -> bool {
        (self.major, self.minor, self.patch) >= (MIN_MAJOR, MIN_MINOR, MIN_PATCH)
    }
}

/// Parse tshark `--version` output into a `TsharkVersion`.
///
/// Finds the first whitespace-delimited token that starts with a digit,
/// splits it on `.`, and parses three numeric components.
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

/// Attempt to run `tshark --version` at the given path and parse the output.
fn probe(path: &str) -> Result<(PathBuf, TsharkVersion), TsharkError> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|e| TsharkError::NotFound(format!("{path}: {e}")))?;

    if !output.status.success() {
        return Err(TsharkError::NotFound(format!(
            "{path} exited with {}",
            output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_version_output(&stdout)?;
    Ok((PathBuf::from(path), version))
}

/// Discover tshark on the system.
///
/// Checks `PATH` first (via `which tshark`), then falls back to known
/// filesystem locations. Returns the resolved path and parsed version.
/// Returns `TsharkError::UnsupportedVersion` if the discovered version
/// is below 3.0.0.
pub fn discover() -> Result<(PathBuf, TsharkVersion), TsharkError> {
    // Try PATH-resolved tshark first.
    if let Ok(result) = probe("tshark") {
        return check_minimum(result);
    }

    // Fall back to known installation paths.
    for known in KNOWN_PATHS {
        if let Ok(result) = probe(known) {
            return check_minimum(result);
        }
    }

    Err(TsharkError::NotFound(
        "tshark not found in PATH or known locations".into(),
    ))
}

fn check_minimum(
    (path, version): (PathBuf, TsharkVersion),
) -> Result<(PathBuf, TsharkVersion), TsharkError> {
    if version.is_supported() {
        Ok((path, version))
    } else {
        Err(TsharkError::UnsupportedVersion {
            version: version.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_tshark_version() {
        let output = "TShark (Wireshark) 4.6.4 (v4.6.4-0-g93282876538d).";
        let version = parse_version_output(output).unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 6);
        assert_eq!(version.patch, 4);
    }

    #[test]
    fn parses_old_version() {
        let output = "TShark (Wireshark) 2.6.1";
        let version = parse_version_output(output).unwrap();
        assert_eq!(version.major, 2);
        assert_eq!(version.minor, 6);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn rejects_garbage_version() {
        assert!(parse_version_output("not a version string").is_err());
    }

    #[test]
    fn old_version_is_unsupported() {
        let v = TsharkVersion {
            major: 2,
            minor: 6,
            patch: 1,
        };
        assert!(!v.is_supported());
    }

    #[test]
    fn minimum_version_is_supported() {
        let v = TsharkVersion {
            major: 3,
            minor: 0,
            patch: 0,
        };
        assert!(v.is_supported());
    }

    #[test]
    fn display_format() {
        let v = TsharkVersion {
            major: 4,
            minor: 6,
            patch: 4,
        };
        assert_eq!(v.to_string(), "4.6.4");
    }
}
