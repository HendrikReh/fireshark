//! Capture comparison logic.
//!
//! Compares two `BackendCapture` instances and produces a summary of
//! differences: new/missing hosts, protocols, and ports.

use std::collections::{BTreeMap, BTreeSet};

use crate::capture::BackendCapture;

/// Result of comparing two captures.
#[derive(Debug, Clone)]
pub struct CaptureComparison {
    pub a_packet_count: usize,
    pub b_packet_count: usize,
    pub a_stream_count: usize,
    pub b_stream_count: usize,
    /// Hosts present in B but not A, with packet count from B.
    pub new_hosts: Vec<(String, usize)>,
    /// Hosts present in A but not B, with packet count from A.
    pub missing_hosts: Vec<(String, usize)>,
    /// Protocols present in B but not A, with packet count from B.
    pub new_protocols: Vec<(String, usize)>,
    /// Ports present in B but not A, with packet count from B.
    pub new_ports: Vec<(u16, usize)>,
}

/// Compare two captures and return a summary of differences.
pub fn compare(a: &BackendCapture, b: &BackendCapture) -> CaptureComparison {
    let a_hosts = extract_hosts(a.endpoint_counts());
    let b_hosts = extract_hosts(b.endpoint_counts());

    let a_host_set: BTreeSet<&str> = a_hosts.keys().map(|k| k.as_str()).collect();
    let b_host_set: BTreeSet<&str> = b_hosts.keys().map(|k| k.as_str()).collect();

    let mut new_hosts: Vec<(String, usize)> = b_host_set
        .difference(&a_host_set)
        .map(|host| ((*host).to_string(), b_hosts[*host]))
        .collect();
    new_hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut missing_hosts: Vec<(String, usize)> = a_host_set
        .difference(&b_host_set)
        .map(|host| ((*host).to_string(), a_hosts[*host]))
        .collect();
    missing_hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let a_protocols = protocol_map(a.protocol_counts());
    let b_protocols = protocol_map(b.protocol_counts());

    let a_proto_set: BTreeSet<&str> = a_protocols.keys().map(|k| k.as_str()).collect();
    let b_proto_set: BTreeSet<&str> = b_protocols.keys().map(|k| k.as_str()).collect();

    let mut new_protocols: Vec<(String, usize)> = b_proto_set
        .difference(&a_proto_set)
        .map(|proto| ((*proto).to_string(), b_protocols[*proto]))
        .collect();
    new_protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let a_ports = extract_ports(a);
    let b_ports = extract_ports(b);

    let a_port_set: BTreeSet<u16> = a_ports.keys().copied().collect();
    let b_port_set: BTreeSet<u16> = b_ports.keys().copied().collect();

    let mut new_ports: Vec<(u16, usize)> = b_port_set
        .difference(&a_port_set)
        .map(|port| (*port, b_ports[port]))
        .collect();
    new_ports.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    CaptureComparison {
        a_packet_count: a.packet_count(),
        b_packet_count: b.packet_count(),
        a_stream_count: 0,
        b_stream_count: 0,
        new_hosts,
        missing_hosts,
        new_protocols,
        new_ports,
    }
}

/// Extract unique host IPs from endpoint count strings.
///
/// Endpoint strings look like `192.168.1.2:51514` (IPv4) or
/// `[::1]:443` (bracketed IPv6). We extract just the IP part.
fn extract_hosts(endpoint_counts: &[(String, usize)]) -> BTreeMap<String, usize> {
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    for (endpoint, count) in endpoint_counts {
        let host = extract_host(endpoint);
        *hosts.entry(host).or_default() += count;
    }
    hosts
}

/// Extract the host (IP) portion from an endpoint string.
///
/// - `192.168.1.2:51514` -> `192.168.1.2`
/// - `[::1]:443` -> `::1`
/// - `192.168.1.2` -> `192.168.1.2` (no port)
fn extract_host(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix('[') {
        // Bracketed IPv6: [addr]:port
        if let Some(bracket_pos) = rest.find(']') {
            return rest[..bracket_pos].to_string();
        }
    }

    // IPv4 with port: addr:port — but only split on last colon to handle
    // bare IPv6 addresses without brackets.
    if let Some(colon_pos) = endpoint.rfind(':') {
        let maybe_port = &endpoint[colon_pos + 1..];
        // If the part after the last colon parses as a port number, treat
        // everything before it as the host.
        if maybe_port.parse::<u16>().is_ok() {
            // Make sure it's not a bare IPv6 address (multiple colons).
            let before = &endpoint[..colon_pos];
            if !before.contains(':') {
                return before.to_string();
            }
        }
    }

    // Fallback: the whole string is the host.
    endpoint.to_string()
}

/// Build a protocol name -> count map from a sorted vec.
fn protocol_map(protocol_counts: &[(String, usize)]) -> BTreeMap<String, usize> {
    protocol_counts
        .iter()
        .map(|(name, count)| (name.clone(), *count))
        .collect()
}

/// Extract port numbers from packet source/destination strings.
fn extract_ports(capture: &BackendCapture) -> BTreeMap<u16, usize> {
    let mut ports: BTreeMap<u16, usize> = BTreeMap::new();
    for packet in capture.packets() {
        for addr in [&packet.summary.source, &packet.summary.destination] {
            if let Some(port) = extract_port(addr) {
                *ports.entry(port).or_default() += 1;
            }
        }
    }
    ports
}

/// Extract a port number from an address string.
///
/// - `192.168.1.2:443` -> Some(443)
/// - `[::1]:443` -> Some(443)
/// - `192.168.1.2` -> None
fn extract_port(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        // Bracketed IPv6: [addr]:port
        if let Some(bracket_pos) = rest.find(']') {
            let after = &rest[bracket_pos + 1..];
            if let Some(port_str) = after.strip_prefix(':') {
                return port_str.parse().ok();
            }
        }
        return None;
    }

    // IPv4 with port: addr:port
    if let Some(colon_pos) = addr.rfind(':') {
        let before = &addr[..colon_pos];
        let port_str = &addr[colon_pos + 1..];
        // Only treat as port if the part before doesn't contain a colon
        // (which would indicate a bare IPv6 address).
        if !before.contains(':') {
            return port_str.parse().ok();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_ipv4_with_port() {
        assert_eq!(extract_host("192.168.1.2:51514"), "192.168.1.2");
    }

    #[test]
    fn extract_host_ipv6_bracketed() {
        assert_eq!(extract_host("[::1]:443"), "::1");
    }

    #[test]
    fn extract_host_bare_ipv4() {
        assert_eq!(extract_host("192.168.1.2"), "192.168.1.2");
    }

    #[test]
    fn extract_port_ipv4() {
        assert_eq!(extract_port("192.168.1.2:443"), Some(443));
    }

    #[test]
    fn extract_port_ipv6_bracketed() {
        assert_eq!(extract_port("[::1]:8080"), Some(8080));
    }

    #[test]
    fn extract_port_bare_ipv4_no_port() {
        assert_eq!(extract_port("192.168.1.2"), None);
    }

    #[test]
    fn extract_port_empty_string() {
        assert_eq!(extract_port(""), None);
    }
}
