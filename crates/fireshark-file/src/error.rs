use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("failed to read capture file")]
    Io(#[from] std::io::Error),

    #[error("failed to parse capture file")]
    Parse(#[from] pcap_file::PcapError),

    #[error("unsupported capture file format")]
    UnsupportedFormat,
}
