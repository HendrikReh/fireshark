use fireshark_core::{DecodeIssue, DecodeIssueKind, Layer};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PacketSummaryView {
    pub index: usize,
    pub timestamp: Option<String>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub original_len: usize,
    pub has_issues: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PacketDetailView {
    pub index: usize,
    pub timestamp: Option<String>,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub original_len: usize,
    pub has_issues: bool,
    pub layers: Vec<LayerView>,
    pub issues: Vec<DecodeIssueView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DecodeIssueView {
    pub kind: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DecodeIssueEntryView {
    pub packet_index: usize,
    pub kind: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolCountView {
    pub protocol: String,
    pub packet_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EndpointCountView {
    pub endpoint: String,
    pub packet_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingView {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<FindingEvidenceView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingEvidenceView {
    pub packet_indexes: Vec<usize>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenCaptureResponse {
    pub session_id: String,
    pub packet_count: usize,
    pub decode_issue_count: usize,
    pub protocol_counts: Vec<ProtocolCountView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CaptureDescriptionView {
    pub session_id: String,
    pub packet_count: usize,
    pub decode_issue_count: usize,
    pub protocol_counts: Vec<ProtocolCountView>,
    pub top_endpoints: Vec<EndpointCountView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CloseCaptureResponse {
    pub session_id: String,
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PacketListResponse {
    pub packets: Vec<PacketSummaryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DecodeIssueListResponse {
    pub issues: Vec<DecodeIssueEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolSummaryResponse {
    pub protocols: Vec<ProtocolCountView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EndpointListResponse {
    pub endpoints: Vec<EndpointCountView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingListResponse {
    pub findings: Vec<FindingView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum LayerView {
    Unknown,
    Ethernet {
        source: String,
        destination: String,
        ether_type: u16,
    },
    #[serde(rename = "ARP")]
    Arp {
        operation: u16,
        sender_protocol_addr: String,
        target_protocol_addr: String,
    },
    #[serde(rename = "IPv4")]
    Ipv4 {
        source: String,
        destination: String,
        protocol: u8,
        fragment_offset: u16,
        more_fragments: bool,
    },
    #[serde(rename = "IPv6")]
    Ipv6 {
        source: String,
        destination: String,
        next_header: u8,
    },
    #[serde(rename = "TCP")]
    Tcp {
        source_port: u16,
        destination_port: u16,
    },
    #[serde(rename = "UDP")]
    Udp {
        source_port: u16,
        destination_port: u16,
    },
    #[serde(rename = "ICMP")]
    Icmp {
        type_: u8,
        code: u8,
    },
}

impl DecodeIssueView {
    pub fn from_issue(issue: &DecodeIssue) -> Self {
        Self {
            kind: format_issue_kind(issue.kind()),
            offset: issue.offset(),
        }
    }
}

impl LayerView {
    pub fn from_layer(layer: &Layer) -> Self {
        match layer {
            Layer::Unknown => Self::Unknown,
            Layer::Ethernet(layer) => Self::Ethernet {
                source: format_mac(layer.source),
                destination: format_mac(layer.destination),
                ether_type: layer.ether_type,
            },
            Layer::Arp(layer) => Self::Arp {
                operation: layer.operation,
                sender_protocol_addr: layer.sender_protocol_addr.to_string(),
                target_protocol_addr: layer.target_protocol_addr.to_string(),
            },
            Layer::Ipv4(layer) => Self::Ipv4 {
                source: layer.source.to_string(),
                destination: layer.destination.to_string(),
                protocol: layer.protocol,
                fragment_offset: layer.fragment_offset,
                more_fragments: layer.more_fragments,
            },
            Layer::Ipv6(layer) => Self::Ipv6 {
                source: layer.source.to_string(),
                destination: layer.destination.to_string(),
                next_header: layer.next_header,
            },
            Layer::Tcp(layer) => Self::Tcp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
            },
            Layer::Udp(layer) => Self::Udp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
            },
            Layer::Icmp(layer) => Self::Icmp {
                type_: layer.type_,
                code: layer.code,
            },
        }
    }
}

pub fn format_issue_kind(kind: &DecodeIssueKind) -> String {
    match kind {
        DecodeIssueKind::Truncated => "truncated",
        DecodeIssueKind::Malformed => "malformed",
    }
    .to_string()
}

fn format_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}
