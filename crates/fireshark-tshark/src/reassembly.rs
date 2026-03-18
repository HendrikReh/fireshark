//! Stream reassembly types produced by tshark-based analysis.
//!
//! These types represent reassembled stream data obtained via tshark's
//! `follow` and field-extraction capabilities.

/// The follow mode to use when reassembling a stream.
#[derive(Debug, Clone)]
pub enum FollowMode {
    /// Raw TCP byte stream (hex-encoded in tshark output).
    Tcp,
    /// HTTP request/response (ASCII in tshark output).
    Http,
}

/// Direction of data flow within a stream segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    /// Data sent from the connection initiator (Node 0).
    ClientToServer,
    /// Data sent from the responder (Node 1).
    ServerToClient,
}

/// A single directional segment within a reassembled stream.
#[derive(Debug, Clone)]
pub struct StreamSegment {
    pub direction: Direction,
    pub data: Vec<u8>,
}

/// The fully reassembled payload for one TCP/HTTP stream.
#[derive(Debug, Clone)]
pub struct StreamPayload {
    pub stream_id: u32,
    pub client: String,
    pub server: String,
    pub segments: Vec<StreamSegment>,
}

/// Parsed HTTP request/response extracted from an HTTP follow stream.
#[derive(Debug, Clone)]
pub struct HttpExchange {
    pub request_method: String,
    pub request_uri: String,
    pub request_host: Option<String>,
    pub response_status: Option<u16>,
    pub response_reason: Option<String>,
}

/// TLS certificate information extracted via tshark field dissection.
#[derive(Debug, Clone)]
pub struct TlsCertInfo {
    pub packet_index: usize,
    pub common_name: Option<String>,
    pub san_dns_names: Vec<String>,
    pub organization: Option<String>,
}
