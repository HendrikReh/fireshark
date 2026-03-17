//! tshark subprocess backend for fireshark.
//!
//! Provides offline capture analysis via the `tshark` command-line tool.
//! This crate handles discovery, execution, and TSV parsing. The resulting
//! [`TsharkCapture`] is converted to backend-neutral types by `fireshark-backend`.

mod command;
mod error;
mod normalize;
mod version;

pub use command::run_fields;
pub use error::TsharkError;
pub use normalize::{TsharkCapture, TsharkPacket, parse_tsv};
pub use version::{TsharkVersion, discover, parse_version_output};

use std::path::Path;

/// Run tshark against a capture file and return parsed packets.
///
/// Discovers tshark on the system, runs it with `-T fields` output,
/// and parses the TSV into [`TsharkCapture`].
pub fn open(path: impl AsRef<Path>) -> Result<TsharkCapture, TsharkError> {
    let (tshark_path, _version) = discover()?;
    let tsv = run_fields(&tshark_path, path.as_ref())?;
    parse_tsv(&tsv)
}
