use std::net::{Ipv4Addr, Ipv6Addr};

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Layer {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpLayer {
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpLayer {
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpLayer {
    pub type_: u8,
    pub code: u8,
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
        }
    }
}
