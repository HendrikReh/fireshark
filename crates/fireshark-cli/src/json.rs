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
    pub escalated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Serialize)]
pub struct DiffJson {
    pub file_a: DiffFileJson,
    pub file_b: DiffFileJson,
    pub new_hosts: Vec<HostDiffJson>,
    pub missing_hosts: Vec<HostDiffJson>,
    pub new_protocols: Vec<ProtocolDiffJson>,
    pub new_ports: Vec<PortDiffJson>,
}

#[derive(Serialize)]
pub struct DiffFileJson {
    pub path: String,
    pub packet_count: usize,
    pub stream_count: usize,
}

#[derive(Serialize)]
pub struct HostDiffJson {
    pub host: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct ProtocolDiffJson {
    pub name: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct PortDiffJson {
    pub port: u16,
    pub count: usize,
}
