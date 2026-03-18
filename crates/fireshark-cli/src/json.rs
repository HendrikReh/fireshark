//! Serializable types for `--json` JSONL output.

use serde::Serialize;

#[derive(Serialize)]
pub struct PacketJson {
    pub index: usize,
    pub timestamp: Option<String>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub stream_id: Option<u32>,
}

#[derive(Serialize)]
pub struct StatsJson {
    pub packet_count: usize,
    pub stream_count: usize,
    pub duration_seconds: Option<f64>,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub protocols: Vec<ProtocolJson>,
    pub top_endpoints: Vec<EndpointJson>,
}

#[derive(Serialize)]
pub struct ProtocolJson {
    pub name: String,
    pub count: usize,
    pub percent: f64,
}

#[derive(Serialize)]
pub struct EndpointJson {
    pub endpoint: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct IssueJson {
    pub packet_index: usize,
    pub kind: String,
    pub offset: usize,
}

#[derive(Serialize)]
pub struct FindingJson {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub evidence_count: usize,
}
