//! tshark subprocess backend for fireshark.
//!
//! Provides offline capture analysis via the `tshark` command-line tool.

mod error;
mod version;

pub use error::TsharkError;
pub use version::{TsharkVersion, parse_version_output};
