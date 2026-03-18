//! Per-protocol layer rendering for the detail view.
//!
//! Each protocol gets a `render_*` function that writes a human-readable
//! description to a `Write` sink. The public entry point is [`render_layer`],
//! which dispatches on the [`Layer`] variant.

use std::io::{self, Write};

use colored::Colorize;
use fireshark_core::{
    ArpLayer, DnsAnswerData, DnsLayer, EthernetLayer, HttpLayer, IcmpDetail, IcmpLayer, Ipv4Layer,
    Ipv6Layer, Layer, TcpLayer, TlsClientHelloLayer, TlsServerHelloLayer, UdpLayer,
    cipher_suite_name, dns_qtype_name, dns_rcode_name, format_mac, named_group_name, sig_alg_name,
    tls_version_name,
};

use crate::color;

pub fn render_layer<W: Write>(w: &mut W, layer: &Layer) -> io::Result<()> {
    match layer {
        Layer::Unknown => {
            writeln!(w, "{}", "▸ Unknown".color(color::protocol_color("Unknown")))
        }
        Layer::Ethernet(l) => render_ethernet(w, l),
        Layer::Arp(l) => render_arp(w, l),
        Layer::Ipv4(l) => render_ipv4(w, l),
        Layer::Ipv6(l) => render_ipv6(w, l),
        Layer::Tcp(l) => render_tcp(w, l),
        Layer::Udp(l) => render_udp(w, l),
        Layer::Icmp(l) => render_icmp(w, l),
        Layer::Dns(l) => render_dns(w, l),
        Layer::TlsClientHello(l) => render_tls_client_hello(w, l),
        Layer::TlsServerHello(l) => render_tls_server_hello(w, l),
        Layer::Http(l) => render_http(w, l),
    }
}

fn format_flags(flags: &[&str]) -> String {
    if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("] ["))
    }
}

fn render_ethernet<W: Write>(w: &mut W, l: &EthernetLayer) -> io::Result<()> {
    writeln!(
        w,
        "{}",
        "▸ Ethernet".color(color::protocol_color("Ethernet"))
    )?;
    writeln!(w, "    Destination: {}", format_mac(l.destination))?;
    writeln!(w, "    Source:      {}", format_mac(l.source))?;
    writeln!(
        w,
        "    EtherType:   0x{:04x} ({})",
        l.ether_type,
        ether_type_name(l.ether_type)
    )
}

fn render_arp<W: Write>(w: &mut W, l: &ArpLayer) -> io::Result<()> {
    let op = match l.operation {
        1 => "request",
        2 => "reply",
        _ => "unknown",
    };
    writeln!(w, "{}", "▸ ARP".color(color::protocol_color("ARP")))?;
    writeln!(w, "    Operation:  {} ({})", l.operation, op)?;
    writeln!(w, "    Sender IP:  {}", l.sender_protocol_addr)?;
    writeln!(w, "    Target IP:  {}", l.target_protocol_addr)
}

fn render_ipv4<W: Write>(w: &mut W, l: &Ipv4Layer) -> io::Result<()> {
    writeln!(w, "{}", "▸ IPv4".color(color::protocol_color("IPv4")))?;
    writeln!(w, "    Source:      {}", l.source)?;
    writeln!(w, "    Destination: {}", l.destination)?;
    let mut flags = Vec::new();
    if l.dont_fragment {
        flags.push("DF");
    }
    if l.more_fragments {
        flags.push("MF");
    }
    writeln!(
        w,
        "    TTL: {}  Protocol: {} ({})  ID: 0x{:04x}{}",
        l.ttl,
        l.protocol,
        ip_protocol_name(l.protocol),
        l.identification,
        format_flags(&flags)
    )?;
    writeln!(
        w,
        "    DSCP: {}  ECN: {}  Checksum: 0x{:04x}",
        l.dscp, l.ecn, l.header_checksum
    )
}

fn render_ipv6<W: Write>(w: &mut W, l: &Ipv6Layer) -> io::Result<()> {
    writeln!(w, "{}", "▸ IPv6".color(color::protocol_color("IPv6")))?;
    writeln!(w, "    Source:      {}", l.source)?;
    writeln!(w, "    Destination: {}", l.destination)?;
    writeln!(
        w,
        "    Next Header: {} ({})  Hop Limit: {}",
        l.next_header,
        ip_protocol_name(l.next_header),
        l.hop_limit
    )?;
    writeln!(
        w,
        "    Traffic Class: {}  Flow Label: {}",
        l.traffic_class, l.flow_label
    )
}

fn render_tcp<W: Write>(w: &mut W, l: &TcpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ TCP".color(color::protocol_color("TCP")))?;
    let mut flags = Vec::new();
    if l.flags.syn {
        flags.push("SYN");
    }
    if l.flags.ack {
        flags.push("ACK");
    }
    if l.flags.fin {
        flags.push("FIN");
    }
    if l.flags.rst {
        flags.push("RST");
    }
    if l.flags.psh {
        flags.push("PSH");
    }
    if l.flags.urg {
        flags.push("URG");
    }
    if l.flags.ece {
        flags.push("ECE");
    }
    if l.flags.cwr {
        flags.push("CWR");
    }
    writeln!(
        w,
        "    {} → {}  Seq: {}  Ack: {}{}  Win: {}",
        l.source_port,
        l.destination_port,
        l.seq,
        l.ack,
        format_flags(&flags),
        l.window
    )?;
    writeln!(
        w,
        "    Data Offset: {} ({} bytes)",
        l.data_offset,
        usize::from(l.data_offset) * 4
    )
}

fn render_udp<W: Write>(w: &mut W, l: &UdpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ UDP".color(color::protocol_color("UDP")))?;
    writeln!(
        w,
        "    {} → {}  Length: {}",
        l.source_port, l.destination_port, l.length
    )
}

fn render_icmp<W: Write>(w: &mut W, l: &IcmpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ ICMP".color(color::protocol_color("ICMP")))?;
    writeln!(
        w,
        "    Type: {} ({})  Code: {}",
        l.type_,
        icmp_type_name(l.type_),
        l.code
    )?;
    match l.detail {
        Some(IcmpDetail::EchoRequest {
            identifier,
            sequence,
        }) => writeln!(
            w,
            "    Identifier: 0x{identifier:04x}  Sequence: {sequence}"
        ),
        Some(IcmpDetail::EchoReply {
            identifier,
            sequence,
        }) => writeln!(
            w,
            "    Identifier: 0x{identifier:04x}  Sequence: {sequence}"
        ),
        Some(IcmpDetail::DestinationUnreachable { next_hop_mtu }) => {
            writeln!(w, "    Next Hop MTU: {next_hop_mtu}")
        }
        Some(IcmpDetail::Other { rest_of_header }) => {
            writeln!(w, "    Rest of Header: 0x{rest_of_header:08x}")
        }
        None => Ok(()),
    }
}

fn render_dns<W: Write>(w: &mut W, l: &DnsLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ DNS".color(color::protocol_color("DNS")))?;
    let direction = if l.is_response { "Response" } else { "Query" };
    writeln!(
        w,
        "    Transaction ID: 0x{:04x}  [{}]",
        l.transaction_id, direction
    )?;
    if l.is_response && l.rcode != 0 {
        writeln!(
            w,
            "    Questions: {}  Answers: {}  RCODE: {} ({})",
            l.question_count,
            l.answer_count,
            l.rcode,
            dns_rcode_name(l.rcode)
        )?;
    } else {
        writeln!(
            w,
            "    Questions: {}  Answers: {}",
            l.question_count, l.answer_count
        )?;
    }
    match (&l.query_name, l.query_type) {
        (Some(name), Some(qtype)) => {
            writeln!(w, "    Query: {} ({})", name, dns_qtype_name(qtype))?;
        }
        (Some(name), None) => {
            writeln!(w, "    Query: {}", name)?;
        }
        (None, _) => {
            writeln!(w, "    Query: <unparseable>")?;
        }
    }
    for answer in &l.answers {
        match &answer.data {
            DnsAnswerData::A(addr) => {
                writeln!(w, "    Answer: A {} (TTL {})", addr, answer.ttl)?;
            }
            DnsAnswerData::Aaaa(addr) => {
                writeln!(w, "    Answer: AAAA {} (TTL {})", addr, answer.ttl)?;
            }
            DnsAnswerData::Other(bytes) => {
                writeln!(
                    w,
                    "    Answer: Type {} ({} bytes)",
                    answer.record_type,
                    bytes.len()
                )?;
            }
        }
    }
    Ok(())
}

fn render_tls_client_hello<W: Write>(w: &mut W, l: &TlsClientHelloLayer) -> io::Result<()> {
    writeln!(
        w,
        "{}",
        "▸ TLS ClientHello".color(color::protocol_color("TLS"))
    )?;
    writeln!(
        w,
        "    Record Version: {} (0x{:04x})",
        tls_version_name(l.record_version),
        l.record_version
    )?;
    writeln!(
        w,
        "    Client Version: {} (0x{:04x})",
        tls_version_name(l.client_version),
        l.client_version
    )?;
    if let Some(sni) = &l.sni {
        writeln!(w, "    SNI: {sni}")?;
    }
    writeln!(w, "    Cipher Suites ({}):", l.cipher_suites.len())?;
    for cs in &l.cipher_suites {
        writeln!(w, "      {} (0x{:04x})", cipher_suite_name(*cs), cs)?;
    }
    let compression = if l.compression_methods == [0x00] {
        "null"
    } else {
        "other"
    };
    writeln!(w, "    Compression: {compression}")?;
    if !l.alpn.is_empty() {
        writeln!(w, "    ALPN: {}", l.alpn.join(", "))?;
    }
    if !l.supported_versions.is_empty() {
        let versions: Vec<String> = l
            .supported_versions
            .iter()
            .map(|v| format!("{} (0x{:04x})", tls_version_name(*v), v))
            .collect();
        writeln!(w, "    Supported Versions: {}", versions.join(", "))?;
    }
    if !l.signature_algorithms.is_empty() {
        let algs: Vec<String> = l
            .signature_algorithms
            .iter()
            .map(|a| format!("{} (0x{:04x})", sig_alg_name(*a), a))
            .collect();
        writeln!(w, "    Signature Algorithms: {}", algs.join(", "))?;
    }
    if !l.key_share_groups.is_empty() {
        let groups: Vec<String> = l
            .key_share_groups
            .iter()
            .map(|g| format!("{} (0x{:04x})", named_group_name(*g), g))
            .collect();
        writeln!(w, "    Key Share Groups: {}", groups.join(", "))?;
    }
    Ok(())
}

fn render_tls_server_hello<W: Write>(w: &mut W, l: &TlsServerHelloLayer) -> io::Result<()> {
    writeln!(
        w,
        "{}",
        "▸ TLS ServerHello".color(color::protocol_color("TLS"))
    )?;
    writeln!(
        w,
        "    Record Version: {} (0x{:04x})",
        tls_version_name(l.record_version),
        l.record_version
    )?;
    writeln!(
        w,
        "    Server Version: {} (0x{:04x})",
        tls_version_name(l.server_version),
        l.server_version
    )?;
    writeln!(
        w,
        "    Cipher Suite: {} (0x{:04x})",
        cipher_suite_name(l.cipher_suite),
        l.cipher_suite
    )?;
    let compression = if l.compression_method == 0x00 {
        "null"
    } else {
        "other"
    };
    writeln!(w, "    Compression: {compression}")?;
    if let Some(v) = l.selected_version {
        writeln!(
            w,
            "    Selected Version: {} (0x{:04x})",
            tls_version_name(v),
            v
        )?;
    }
    if let Some(alpn) = &l.alpn {
        writeln!(w, "    ALPN: {alpn}")?;
    }
    if let Some(g) = l.key_share_group {
        writeln!(
            w,
            "    Key Share Group: {} (0x{:04x})",
            named_group_name(g),
            g
        )?;
    }
    Ok(())
}

fn render_http<W: Write>(w: &mut W, l: &HttpLayer) -> io::Result<()> {
    writeln!(w, "{}", "▸ HTTP".color(color::protocol_color("HTTP")))?;
    if l.is_request {
        writeln!(
            w,
            "    {} {} {}",
            l.method.as_deref().unwrap_or("?"),
            l.uri.as_deref().unwrap_or("?"),
            l.version
        )?;
    } else {
        writeln!(
            w,
            "    {} {} {}",
            l.version,
            l.status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            l.reason.as_deref().unwrap_or("")
        )?;
    }
    if let Some(host) = &l.host {
        writeln!(w, "    Host: {host}")?;
    }
    if let Some(ct) = &l.content_type {
        writeln!(w, "    Content-Type: {ct}")?;
    }
    if let Some(cl) = l.content_length {
        writeln!(w, "    Content-Length: {cl}")?;
    }
    Ok(())
}

fn ether_type_name(ether_type: u16) -> &'static str {
    match ether_type {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        _ => "Unknown",
    }
}

fn ip_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Unknown",
    }
}

fn icmp_type_name(type_: u8) -> &'static str {
    match type_ {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        128 => "Echo Request (v6)",
        129 => "Echo Reply (v6)",
        _ => "Unknown",
    }
}
