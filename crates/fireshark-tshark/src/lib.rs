//! tshark subprocess backend for fireshark.
//!
//! Provides offline capture analysis via the `tshark` command-line tool.
//! This crate handles discovery, execution, and TSV parsing. The resulting
//! [`TsharkCapture`] is converted to backend-neutral types by `fireshark-backend`.

pub mod certs;
pub(crate) mod command;
mod error;
pub mod follow;
mod normalize;
pub mod reassembly;
pub mod version;

pub use command::run_fields;
pub use error::TsharkError;
pub use normalize::{TsharkCapture, TsharkPacket, parse_tsv};
pub use reassembly::{
    Direction, FollowMode, HttpExchange, StreamPayload, StreamSegment, TlsCertInfo,
};
pub use version::{TsharkVersion, discover, parse_version_output};

use std::path::Path;

/// Returns `true` if a usable `tshark` binary is found on the system.
///
/// Useful in test code for skipping tests that require tshark.
pub fn is_available() -> bool {
    discover().is_ok()
}

/// Run tshark against a capture file and return parsed packets.
///
/// Discovers tshark on the system, runs it with `-T fields` output,
/// and parses the TSV into [`TsharkCapture`].
pub fn open(path: impl AsRef<Path>) -> Result<TsharkCapture, TsharkError> {
    let (tshark_path, _version) = discover()?;
    let tsv = run_fields(&tshark_path, path.as_ref())?;
    parse_tsv(&tsv)
}
