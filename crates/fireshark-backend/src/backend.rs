use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Native,
    Tshark,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Tshark => write!(f, "tshark"),
        }
    }
}

impl FromStr for BackendKind {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "native" => Ok(Self::Native),
            "tshark" => Ok(Self::Tshark),
            other => Err(format!("unsupported backend: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    pub supports_streams: bool,
    pub supports_decode_issues: bool,
    pub supports_native_filter: bool,
    pub supports_layer_spans: bool,
    pub supports_audit: bool,
    pub supports_reassembly: bool,
}
