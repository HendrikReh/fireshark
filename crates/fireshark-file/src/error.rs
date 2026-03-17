use thiserror::Error;

use pcap_file::DataLink;

/// Errors that can occur when opening or reading a capture file.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("failed to read capture file")]
    Io(#[from] std::io::Error),

    #[error("failed to parse capture file")]
    Parse(#[from] pcap_file::PcapError),

    #[error("unsupported capture file format")]
    UnsupportedFormat,

    #[error("unsupported capture link type: {datalink:?}")]
    UnsupportedLinkType { datalink: DataLink },
}
