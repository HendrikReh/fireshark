use fireshark_core::{DecodeIssue, DecodeIssueKind, DnsAnswerData, Layer};
use fireshark_dissectors::tls;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TcpFlagsView {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum IcmpDetailView {
    EchoRequest { identifier: u16, sequence: u16 },
    EchoReply { identifier: u16, sequence: u16 },
    DestinationUnreachable { next_hop_mtu: u16 },
    Other { rest_of_header: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DnsAnswerView {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CipherSuiteView {
    pub id: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignatureAlgorithmView {
    pub id: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NamedGroupView {
    pub id: u16,
    pub name: String,
}

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
pub struct StreamView {
    pub id: u32,
    pub protocol: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub packet_count: usize,
    pub byte_count: usize,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamListResponse {
    pub streams: Vec<StreamView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamPacketsResponse {
    pub stream: StreamView,
    pub packets: Vec<PacketSummaryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CaptureSummaryView {
    pub packet_count: usize,
    pub stream_count: usize,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub duration_ms: Option<u64>,
    pub protocols: Vec<ProtocolCountView>,
    pub top_endpoints: Vec<EndpointCountView>,
    pub finding_count: usize,
}

impl StreamView {
    pub fn from_metadata(meta: &fireshark_core::StreamMetadata) -> Self {
        let duration_ms = match (meta.first_seen, meta.last_seen) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_millis() as u64),
            _ => None,
        };

        Self {
            id: meta.id,
            protocol: meta.key.protocol_name().to_string(),
            endpoint_a: format_stream_endpoint(meta.key.addr_lo, meta.key.port_lo),
            endpoint_b: format_stream_endpoint(meta.key.addr_hi, meta.key.port_hi),
            packet_count: meta.packet_count,
            byte_count: meta.byte_count,
            duration_ms,
        }
    }
}

fn format_stream_endpoint(addr: std::net::IpAddr, port: u16) -> String {
    match addr {
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
    }
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
        ttl: u8,
        identification: u16,
        dscp: u8,
        ecn: u8,
        dont_fragment: bool,
        header_checksum: u16,
    },
    #[serde(rename = "IPv6")]
    Ipv6 {
        source: String,
        destination: String,
        next_header: u8,
        traffic_class: u8,
        flow_label: u32,
        hop_limit: u8,
    },
    #[serde(rename = "TCP")]
    Tcp {
        source_port: u16,
        destination_port: u16,
        seq: u32,
        ack: u32,
        data_offset: u8,
        flags: TcpFlagsView,
        window: u16,
    },
    #[serde(rename = "UDP")]
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
    },
    #[serde(rename = "ICMP")]
    Icmp {
        type_: u8,
        code: u8,
        detail: Option<IcmpDetailView>,
    },
    #[serde(rename = "DNS")]
    Dns {
        transaction_id: u16,
        is_response: bool,
        opcode: u8,
        question_count: u16,
        answer_count: u16,
        query_name: Option<String>,
        query_type: Option<u16>,
        answers: Vec<DnsAnswerView>,
    },
    TlsClientHello {
        record_version: u16,
        client_version: u16,
        cipher_suites: Vec<CipherSuiteView>,
        compression_methods: Vec<u8>,
        sni: Option<String>,
        alpn: Vec<String>,
        supported_versions: Vec<u16>,
        signature_algorithms: Vec<SignatureAlgorithmView>,
        key_share_groups: Vec<NamedGroupView>,
    },
    TlsServerHello {
        record_version: u16,
        server_version: u16,
        cipher_suite: CipherSuiteView,
        compression_method: u8,
        selected_version: Option<u16>,
        alpn: Option<String>,
        key_share_group: Option<NamedGroupView>,
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
                ttl: layer.ttl,
                identification: layer.identification,
                dscp: layer.dscp,
                ecn: layer.ecn,
                dont_fragment: layer.dont_fragment,
                header_checksum: layer.header_checksum,
            },
            Layer::Ipv6(layer) => Self::Ipv6 {
                source: layer.source.to_string(),
                destination: layer.destination.to_string(),
                next_header: layer.next_header,
                traffic_class: layer.traffic_class,
                flow_label: layer.flow_label,
                hop_limit: layer.hop_limit,
            },
            Layer::Tcp(layer) => Self::Tcp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
                seq: layer.seq,
                ack: layer.ack,
                data_offset: layer.data_offset,
                flags: TcpFlagsView {
                    fin: layer.flags.fin,
                    syn: layer.flags.syn,
                    rst: layer.flags.rst,
                    psh: layer.flags.psh,
                    ack: layer.flags.ack,
                    urg: layer.flags.urg,
                    ece: layer.flags.ece,
                    cwr: layer.flags.cwr,
                },
                window: layer.window,
            },
            Layer::Udp(layer) => Self::Udp {
                source_port: layer.source_port,
                destination_port: layer.destination_port,
                length: layer.length,
            },
            Layer::Icmp(layer) => Self::Icmp {
                type_: layer.type_,
                code: layer.code,
                detail: layer.detail.map(|d| match d {
                    fireshark_core::IcmpDetail::EchoRequest {
                        identifier,
                        sequence,
                    } => IcmpDetailView::EchoRequest {
                        identifier,
                        sequence,
                    },
                    fireshark_core::IcmpDetail::EchoReply {
                        identifier,
                        sequence,
                    } => IcmpDetailView::EchoReply {
                        identifier,
                        sequence,
                    },
                    fireshark_core::IcmpDetail::DestinationUnreachable { next_hop_mtu } => {
                        IcmpDetailView::DestinationUnreachable { next_hop_mtu }
                    }
                    fireshark_core::IcmpDetail::Other { rest_of_header } => {
                        IcmpDetailView::Other { rest_of_header }
                    }
                }),
            },
            Layer::Dns(layer) => Self::Dns {
                transaction_id: layer.transaction_id,
                is_response: layer.is_response,
                opcode: layer.opcode,
                question_count: layer.question_count,
                answer_count: layer.answer_count,
                query_name: layer.query_name.clone(),
                query_type: layer.query_type,
                answers: layer
                    .answers
                    .iter()
                    .map(|a| DnsAnswerView {
                        name: a.name.clone(),
                        record_type: a.record_type,
                        ttl: a.ttl,
                        data: match &a.data {
                            DnsAnswerData::A(addr) => addr.to_string(),
                            DnsAnswerData::Aaaa(addr) => addr.to_string(),
                            DnsAnswerData::Other(bytes) => format!("{} bytes", bytes.len()),
                        },
                    })
                    .collect(),
            },
            Layer::TlsClientHello(layer) => Self::TlsClientHello {
                record_version: layer.record_version,
                client_version: layer.client_version,
                cipher_suites: layer
                    .cipher_suites
                    .iter()
                    .map(|&id| CipherSuiteView {
                        id,
                        name: tls::cipher_suite_name(id).to_string(),
                    })
                    .collect(),
                compression_methods: layer.compression_methods.clone(),
                sni: layer.sni.clone(),
                alpn: layer.alpn.clone(),
                supported_versions: layer.supported_versions.clone(),
                signature_algorithms: layer
                    .signature_algorithms
                    .iter()
                    .map(|&id| SignatureAlgorithmView {
                        id,
                        name: tls::sig_alg_name(id).to_string(),
                    })
                    .collect(),
                key_share_groups: layer
                    .key_share_groups
                    .iter()
                    .map(|&id| NamedGroupView {
                        id,
                        name: tls::named_group_name(id).to_string(),
                    })
                    .collect(),
            },
            Layer::TlsServerHello(layer) => Self::TlsServerHello {
                record_version: layer.record_version,
                server_version: layer.server_version,
                cipher_suite: CipherSuiteView {
                    id: layer.cipher_suite,
                    name: tls::cipher_suite_name(layer.cipher_suite).to_string(),
                },
                compression_method: layer.compression_method,
                selected_version: layer.selected_version,
                alpn: layer.alpn.clone(),
                key_share_group: layer.key_share_group.map(|id| NamedGroupView {
                    id,
                    name: tls::named_group_name(id).to_string(),
                }),
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
