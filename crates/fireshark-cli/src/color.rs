use colored::{Color, ColoredString, Colorize};

/// Return the ANSI color for a protocol name.
pub fn protocol_color(protocol: &str) -> Color {
    if protocol.eq_ignore_ascii_case("tcp") {
        Color::Green
    } else if protocol.eq_ignore_ascii_case("udp") {
        Color::Blue
    } else if protocol.eq_ignore_ascii_case("arp") {
        Color::Yellow
    } else if protocol.eq_ignore_ascii_case("icmp") {
        Color::Cyan
    } else if protocol.eq_ignore_ascii_case("ipv4")
        || protocol.eq_ignore_ascii_case("ipv6")
        || protocol.eq_ignore_ascii_case("ethernet")
    {
        Color::White
    } else {
        Color::Red
    }
}

/// Colorize an entire summary line based on the protocol name.
///
/// Color map (Wireshark-inspired):
/// - TCP → green
/// - UDP → blue
/// - ARP → yellow
/// - ICMP → cyan
/// - Ethernet/IPv4/IPv6 → white
/// - Unknown/other → red
pub fn colorize(protocol: &str, line: &str) -> ColoredString {
    line.color(protocol_color(protocol))
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

    #[test]
    fn ethernet_is_white() {
        let cs = colorize("Ethernet", "test");
        assert_eq!(cs.fgcolor, Some(Color::White));
    }

    #[test]
    fn protocol_color_returns_correct_colors() {
        assert_eq!(protocol_color("TCP"), Color::Green);
        assert_eq!(protocol_color("UDP"), Color::Blue);
        assert_eq!(protocol_color("Ethernet"), Color::White);
        assert_eq!(protocol_color("Unknown"), Color::Red);
    }
}
