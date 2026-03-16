use std::io::{self, Write};
use std::path::Path;

use colored::Colorize;
use fireshark_core::{
    ArpLayer, DecodedFrame, EthernetLayer, IcmpDetail, IcmpLayer, Ipv4Layer, Ipv6Layer, Layer,
    LayerSpan, Pipeline, TcpLayer, UdpLayer,
};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::hexdump;
use crate::timestamp;

pub fn run(path: &Path, packet_number: usize) -> Result<(), Box<dyn std::error::Error>> {
    if packet_number == 0 {
        return Err("packet number must be >= 1".into());
    }

    let reader = CaptureReader::open(path)?;
    let index = packet_number - 1;

    let decoded = Pipeline::new(reader, decode_packet)
        .nth(index)
        .ok_or_else(|| format!("packet {packet_number} not found (capture has fewer packets)"))?
        .map_err(|e| format!("decode error at packet {packet_number}: {e}"))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    render_header(&mut out, &decoded, packet_number)?;
    render_layer_tree(&mut out, &decoded)?;

    let span_colors: Vec<(LayerSpan, &str)> = decoded
        .packet()
        .layers()
        .iter()
        .zip(decoded.packet().spans())
        .map(|(layer, span)| (*span, layer.name()))
        .collect();
    hexdump::render(&mut out, decoded.frame().data(), &span_colors)?;

    Ok(())
}

fn render_header<W: Write>(
    w: &mut W,
    decoded: &DecodedFrame,
    packet_number: usize,
) -> io::Result<()> {
    let len = decoded.frame().captured_len();
    let ts = match decoded.frame().timestamp() {
        Some(d) => timestamp::format_utc(d),
        None => String::from("-"),
    };
    writeln!(w, "Packet {packet_number} · {len} bytes · {ts}")?;
    writeln!(w, "─────────────────────────────────────────────────")
}

fn render_layer_tree<W: Write>(w: &mut W, decoded: &DecodedFrame) -> io::Result<()> {
    for layer in decoded.packet().layers() {
        render_layer(w, layer)?;
    }
    for issue in decoded.packet().issues() {
        let kind = match issue.kind() {
            fireshark_core::DecodeIssueKind::Truncated => "Truncated",
            fireshark_core::DecodeIssueKind::Malformed => "Malformed",
        };
        writeln!(w, "{} {} at offset {}", "⚠".red(), kind, issue.offset())?;
    }
    Ok(())
}

fn render_layer<W: Write>(w: &mut W, layer: &Layer) -> io::Result<()> {
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
    let flag_str = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("] ["))
    };
    writeln!(
        w,
        "    TTL: {}  Protocol: {} ({})  ID: 0x{:04x}{}",
        l.ttl,
        l.protocol,
        ip_protocol_name(l.protocol),
        l.identification,
        flag_str
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
    let flag_str = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("] ["))
    };
    writeln!(
        w,
        "    {} → {}  Seq: {}  Ack: {}{}  Win: {}",
        l.source_port, l.destination_port, l.seq, l.ack, flag_str, l.window
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

fn format_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
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
