use colored::{ColoredString, Colorize};

/// Colorize an entire summary line based on the protocol name.
///
/// Color map (Wireshark-inspired):
/// - TCP → green
/// - UDP → blue
/// - ARP → yellow
/// - ICMP → cyan
/// - IPv4/IPv6 → white
/// - Unknown/other → red
pub fn colorize(protocol: &str, line: &str) -> ColoredString {
    match protocol.to_ascii_uppercase().as_str() {
        "TCP" => line.green(),
        "UDP" => line.blue(),
        "ARP" => line.yellow(),
        "ICMP" => line.cyan(),
        "IPV4" | "IPV6" => line.white(),
        _ => line.red(),
    }
}

#[cfg(test)]
mod tests {
    use colored::Color;

    use super::*;

    #[test]
    fn tcp_lines_are_green() {
        let cs = colorize("TCP", "test line");
        assert_eq!(cs.fgcolor, Some(Color::Green));
    }

    #[test]
    fn udp_lines_are_blue() {
        let cs = colorize("UDP", "test line");
        assert_eq!(cs.fgcolor, Some(Color::Blue));
    }

    #[test]
    fn arp_lines_are_yellow() {
        let cs = colorize("ARP", "test line");
        assert_eq!(cs.fgcolor, Some(Color::Yellow));
    }

    #[test]
    fn icmp_lines_are_cyan() {
        let cs = colorize("ICMP", "test line");
        assert_eq!(cs.fgcolor, Some(Color::Cyan));
    }

    #[test]
    fn ipv4_lines_are_white() {
        let cs = colorize("IPv4", "test line");
        assert_eq!(cs.fgcolor, Some(Color::White));
    }

    #[test]
    fn unknown_protocol_is_red() {
        let cs = colorize("Unknown", "test line");
        assert_eq!(cs.fgcolor, Some(Color::Red));
    }

    #[test]
    fn colorize_is_case_insensitive() {
        let lower = colorize("tcp", "line");
        let upper = colorize("TCP", "line");
        assert_eq!(lower, upper);
    }
}
