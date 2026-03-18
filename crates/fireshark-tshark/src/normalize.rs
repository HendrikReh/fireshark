use std::time::Duration;

use crate::TsharkError;

/// A single packet parsed from tshark TSV output.
#[derive(Debug, Clone)]
pub struct TsharkPacket {
    /// Frame number from tshark (1-indexed).
    pub frame_number: usize,
    /// Epoch timestamp.
    pub timestamp: Option<Duration>,
    /// Frame length in bytes.
    pub length: usize,
    /// Protocol name from the tshark Protocol column.
    pub protocol: String,
    /// Info string from the tshark Info column.
    pub info: String,
    /// Source address (IP or IPv6), possibly with port appended.
    pub source: String,
    /// Destination address (IP or IPv6), possibly with port appended.
    pub destination: String,
}

/// Result of parsing a tshark capture.
#[derive(Debug, Clone)]
pub struct TsharkCapture {
    pub packets: Vec<TsharkPacket>,
}

/// Column indices in the tshark TSV output (must match [`crate::command::FIELD_NAMES`]).
mod col {
    pub const FRAME_NUMBER: usize = 0;
    pub const FRAME_TIME_EPOCH: usize = 1;
    pub const FRAME_LEN: usize = 2;
    // cap_len at index 3 — not currently used, but reserved
    pub const PROTOCOL: usize = 4;
    pub const INFO: usize = 5;
    pub const IP_SRC: usize = 6;
    pub const IP_DST: usize = 7;
    pub const IPV6_SRC: usize = 8;
    pub const IPV6_DST: usize = 9;
    pub const TCP_SRCPORT: usize = 10;
    pub const TCP_DSTPORT: usize = 11;
    pub const UDP_SRCPORT: usize = 12;
    pub const UDP_DSTPORT: usize = 13;
    pub const EXPECTED_COLUMNS: usize = 14;
}

/// Parse raw tshark `-T fields` TSV output into a [`TsharkCapture`].
pub fn parse_tsv(tsv: &str) -> Result<TsharkCapture, TsharkError> {
    let mut lines = tsv.lines();

    // Skip the header line.
    let _header = lines.next().ok_or_else(|| {
        TsharkError::ParseOutput("tshark output is empty (no header line)".into())
    })?;

    let mut packets = Vec::new();

    for (line_idx, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < col::EXPECTED_COLUMNS {
            return Err(TsharkError::ParseOutput(format!(
                "line {}: expected {} columns, got {}",
                line_idx + 2, // +2 for 1-indexed + header
                col::EXPECTED_COLUMNS,
                fields.len()
            )));
        }

        let frame_number: usize = fields[col::FRAME_NUMBER].parse().map_err(|e| {
            TsharkError::ParseOutput(format!("line {}: frame.number: {e}", line_idx + 2))
        })?;

        let timestamp = parse_timestamp(fields[col::FRAME_TIME_EPOCH]);

        let length: usize = fields[col::FRAME_LEN].parse().map_err(|e| {
            TsharkError::ParseOutput(format!("line {}: frame.len: {e}", line_idx + 2))
        })?;

        let protocol = fields[col::PROTOCOL].to_string();
        let info = fields[col::INFO].to_string();

        // Build source: prefer IPv4, fall back to IPv6.
        let raw_src = non_empty(fields[col::IP_SRC])
            .or_else(|| non_empty(fields[col::IPV6_SRC]))
            .unwrap_or_default();

        let raw_dst = non_empty(fields[col::IP_DST])
            .or_else(|| non_empty(fields[col::IPV6_DST]))
            .unwrap_or_default();

        // Append port if available (TCP takes precedence over UDP).
        let src_port =
            non_empty(fields[col::TCP_SRCPORT]).or_else(|| non_empty(fields[col::UDP_SRCPORT]));
        let dst_port =
            non_empty(fields[col::TCP_DSTPORT]).or_else(|| non_empty(fields[col::UDP_DSTPORT]));

        let source = append_port(raw_src, src_port);
        let destination = append_port(raw_dst, dst_port);

        packets.push(TsharkPacket {
            frame_number,
            timestamp,
            length,
            protocol,
            info,
            source,
            destination,
        });
    }

    Ok(TsharkCapture { packets })
}

/// Parse a tshark epoch timestamp string into a `Duration`.
fn parse_timestamp(s: &str) -> Option<Duration> {
    let secs_f64: f64 = s.parse().ok()?;
    if secs_f64 < 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(secs_f64))
}

/// Return `Some(s)` if non-empty, `None` otherwise.
fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Append `:port` to an address string if a port is present.
///
/// IPv6 addresses are bracketed (`[addr]:port`) to avoid ambiguity with
/// the colon separators in the address itself.
fn append_port(addr: &str, port: Option<&str>) -> String {
    match port {
        Some(p) if !addr.is_empty() && addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) if !addr.is_empty() => format!("{addr}:{p}"),
        _ => addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tsv() -> String {
        let header = "frame.number\tframe.time_epoch\tframe.len\tframe.cap_len\t\
                       _ws.col.protocol\t_ws.col.info\tip.src\tip.dst\t\
                       ipv6.src\tipv6.dst\ttcp.srcport\ttcp.dstport\t\
                       udp.srcport\tudp.dstport";
        let row = "1\t1.000000000\t54\t54\tTCP\t\
                   51514 \u{2192} 443 [SYN] Seq=0 Win=1024 Len=0\t\
                   192.0.2.10\t198.51.100.20\t\t\t51514\t443\t\t";
        format!("{header}\n{row}\n")
    }

    #[test]
    fn parses_single_packet_tsv() {
        let capture = parse_tsv(&sample_tsv()).unwrap();
        assert_eq!(capture.packets.len(), 1);
        let pkt = &capture.packets[0];
        assert_eq!(pkt.frame_number, 1);
        assert_eq!(pkt.protocol, "TCP");
        assert_eq!(pkt.source, "192.0.2.10:51514");
        assert_eq!(pkt.destination, "198.51.100.20:443");
        assert_eq!(pkt.length, 54);
        assert!(pkt.timestamp.is_some());
    }

    #[test]
    fn parses_empty_body() {
        let tsv = "frame.number\tframe.time_epoch\tframe.len\tframe.cap_len\t\
                   _ws.col.protocol\t_ws.col.info\tip.src\tip.dst\t\
                   ipv6.src\tipv6.dst\ttcp.srcport\ttcp.dstport\t\
                   udp.srcport\tudp.dstport\n";
        let capture = parse_tsv(tsv).unwrap();
        assert_eq!(capture.packets.len(), 0);
    }

    #[test]
    fn rejects_too_few_columns() {
        let tsv = "header\n1\t2\t3\n";
        assert!(parse_tsv(tsv).is_err());
    }

    #[test]
    fn udp_port_appended() {
        let header = "frame.number\tframe.time_epoch\tframe.len\tframe.cap_len\t\
                       _ws.col.protocol\t_ws.col.info\tip.src\tip.dst\t\
                       ipv6.src\tipv6.dst\ttcp.srcport\ttcp.dstport\t\
                       udp.srcport\tudp.dstport";
        let row = "1\t1.000000000\t70\t70\tDNS\tStandard query\t\
                   192.168.1.1\t8.8.8.8\t\t\t\t\t12345\t53";
        let tsv = format!("{header}\n{row}\n");
        let capture = parse_tsv(&tsv).unwrap();
        let pkt = &capture.packets[0];
        assert_eq!(pkt.source, "192.168.1.1:12345");
        assert_eq!(pkt.destination, "8.8.8.8:53");
    }

    #[test]
    fn ipv6_endpoints_bracketed_with_port() {
        let header = "frame.number\tframe.time_epoch\tframe.len\tframe.cap_len\t\
                       _ws.col.protocol\t_ws.col.info\tip.src\tip.dst\t\
                       ipv6.src\tipv6.dst\ttcp.srcport\ttcp.dstport\t\
                       udp.srcport\tudp.dstport";
        let row = "1\t1.000000000\t74\t74\tTCP\tinfo\t\t\t\
                   2001:db8::1\t2001:db8::2\t51514\t443\t\t";
        let tsv = format!("{header}\n{row}\n");
        let capture = parse_tsv(&tsv).unwrap();
        let pkt = &capture.packets[0];
        assert_eq!(pkt.source, "[2001:db8::1]:51514");
        assert_eq!(pkt.destination, "[2001:db8::2]:443");
    }

    #[test]
    fn ipv6_endpoint_without_port_not_bracketed() {
        // When there's no port, IPv6 addresses stay bare
        let addr = append_port("2001:db8::1", None);
        assert_eq!(addr, "2001:db8::1");
    }
}
