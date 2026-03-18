//! Protocol layer types used throughout the dissection pipeline.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpDetail {
    EchoRequest { identifier: u16, sequence: u16 },
    EchoReply { identifier: u16, sequence: u16 },
    DestinationUnreachable { next_hop_mtu: u16 },
    Other { rest_of_header: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetLayer {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpLayer {
    pub operation: u16,
    pub sender_protocol_addr: Ipv4Addr,
    pub target_protocol_addr: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Layer {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub identification: u16,
    pub dscp: u8,
    pub ecn: u8,
    pub dont_fragment: bool,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub header_checksum: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Layer {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hop_limit: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpLayer {
    pub source_port: u16,
    pub destination_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpLayer {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpLayer {
    pub type_: u8,
    pub code: u8,
    pub detail: Option<IcmpDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: DnsAnswerData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswerData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLayer {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub query_name: Option<String>,
    pub query_type: Option<u16>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloLayer {
    pub record_version: u16,
    pub client_version: u16,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHelloLayer {
    pub record_version: u16,
    pub server_version: u16,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub selected_version: Option<u16>,
    pub alpn: Option<String>,
    pub key_share_group: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpLayer {
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: String,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    Unknown,
    Ethernet(EthernetLayer),
    Arp(ArpLayer),
    Ipv4(Ipv4Layer),
    Ipv6(Ipv6Layer),
    Tcp(TcpLayer),
    Udp(UdpLayer),
    Icmp(IcmpLayer),
    Dns(DnsLayer),
    TlsClientHello(TlsClientHelloLayer),
    TlsServerHello(TlsServerHelloLayer),
    Http(HttpLayer),
}

/// Format a 6-byte MAC address as colon-separated hex.
pub fn format_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

impl Layer {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Ethernet(_) => "Ethernet",
            Self::Arp(_) => "ARP",
            Self::Ipv4(_) => "IPv4",
            Self::Ipv6(_) => "IPv6",
            Self::Tcp(_) => "TCP",
            Self::Udp(_) => "UDP",
            Self::Icmp(_) => "ICMP",
            Self::Dns(_) => "DNS",
            Self::TlsClientHello(_) => "TLS",
            Self::TlsServerHello(_) => "TLS",
            Self::Http(_) => "HTTP",
        }
    }
}
