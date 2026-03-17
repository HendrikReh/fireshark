//! TCP/UDP conversation tracking by canonical 5-tuple.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::{DecodedFrame, Layer};

/// Canonical 5-tuple identifying a bidirectional conversation.
///
/// Both directions normalize to the same key: the "lower" endpoint
/// (by `(addr, port)` lexicographic order) always occupies `addr_lo`/`port_lo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub addr_lo: IpAddr,
    pub port_lo: u16,
    pub addr_hi: IpAddr,
    pub port_hi: u16,
    pub protocol: u8,
}

impl StreamKey {
    /// Create a normalized key from source/destination addresses and ports.
    ///
    /// The lower `(addr, port)` pair is placed first so that both directions
    /// of the same conversation produce the same key.
    pub fn new(
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if (src_addr, src_port) <= (dst_addr, dst_port) {
            Self {
                addr_lo: src_addr,
                port_lo: src_port,
                addr_hi: dst_addr,
                port_hi: dst_port,
                protocol,
            }
        } else {
            Self {
                addr_lo: dst_addr,
                port_lo: dst_port,
                addr_hi: src_addr,
                port_hi: src_port,
                protocol,
            }
        }
    }

    /// Protocol name for display.
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown",
        }
    }
}

/// Per-stream statistics accumulated during iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMetadata {
    pub id: u32,
    pub key: StreamKey,
    pub packet_count: usize,
    pub byte_count: usize,
    pub first_seen: Option<Duration>,
    pub last_seen: Option<Duration>,
    /// Bitwise OR of all TCP flag bytes seen in this stream.
    pub tcp_flags_seen: u8,
    /// Whether a SYN+ACK packet was observed in this stream.
    pub syn_ack_seen: bool,
    /// Count of packets with RST flag set.
    pub rst_count: u16,
}

/// Assigns and tracks stream IDs for TCP/UDP conversations.
///
/// Each unique `StreamKey` receives a monotonically increasing `u32` stream ID
/// starting at 0. Call `assign()` for each decoded frame; packets without a
/// transport layer receive `None`.
#[derive(Debug, Clone)]
pub struct StreamTracker {
    streams: HashMap<StreamKey, u32>,
    metadata: Vec<StreamMetadata>,
}

impl StreamTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            metadata: Vec::new(),
        }
    }

    /// Assign a stream ID to the given decoded frame.
    ///
    /// Returns `None` if the packet has no IP + transport layer pair
    /// (e.g. ARP, ICMP-only, or Ethernet-only).
    pub fn assign(&mut self, decoded: &DecodedFrame) -> Option<u32> {
        let (src_addr, src_port, dst_addr, dst_port, protocol) =
            extract_transport_tuple(decoded.packet().layers())?;
        let key = StreamKey::new(src_addr, src_port, dst_addr, dst_port, protocol);

        let id = if let Some(&id) = self.streams.get(&key) {
            id
        } else {
            let id = self.metadata.len() as u32;
            self.streams.insert(key.clone(), id);
            self.metadata.push(StreamMetadata {
                id,
                key,
                packet_count: 0,
                byte_count: 0,
                first_seen: None,
                last_seen: None,
                tcp_flags_seen: 0,
                syn_ack_seen: false,
                rst_count: 0,
            });
            id
        };

        let meta = &mut self.metadata[id as usize];
        meta.packet_count += 1;
        meta.byte_count += decoded.frame().captured_len();
        let ts = decoded.frame().timestamp();
        if meta.first_seen.is_none() {
            meta.first_seen = ts;
        }
        meta.last_seen = ts;

        if let Some(Layer::Tcp(tcp)) = decoded
            .packet()
            .layers()
            .iter()
            .find(|l| matches!(l, Layer::Tcp(_)))
        {
            let flags_byte = (tcp.flags.fin as u8)
                | ((tcp.flags.syn as u8) << 1)
                | ((tcp.flags.rst as u8) << 2)
                | ((tcp.flags.psh as u8) << 3)
                | ((tcp.flags.ack as u8) << 4)
                | ((tcp.flags.urg as u8) << 5)
                | ((tcp.flags.ece as u8) << 6)
                | ((tcp.flags.cwr as u8) << 7);
            meta.tcp_flags_seen |= flags_byte;
            if tcp.flags.syn && tcp.flags.ack {
                meta.syn_ack_seen = true;
            }
            if tcp.flags.rst {
                meta.rst_count = meta.rst_count.saturating_add(1);
            }
        }

        Some(id)
    }

    /// All stream metadata in ID order.
    pub fn streams(&self) -> &[StreamMetadata] {
        &self.metadata
    }

    /// Look up metadata for a single stream.
    pub fn get(&self, stream_id: u32) -> Option<&StreamMetadata> {
        self.metadata.get(stream_id as usize)
    }

    /// Number of distinct streams observed.
    pub fn stream_count(&self) -> usize {
        self.metadata.len()
    }
}

impl Default for StreamTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract both IP addresses, transport ports, and protocol number from packet layers.
///
/// Returns `(src_addr, src_port, dst_addr, dst_port, protocol)`. The protocol
/// number is read from the IP layer (`Ipv4Layer.protocol` or `Ipv6Layer.next_header`)
/// rather than being inferred from the transport layer type.
fn extract_transport_tuple(layers: &[Layer]) -> Option<(IpAddr, u16, IpAddr, u16, u8)> {
    let mut addrs: Option<(IpAddr, IpAddr, u8)> = None;
    let mut ports: Option<(u16, u16)> = None;

    for layer in layers {
        match layer {
            Layer::Ipv4(l) => {
                addrs = Some((IpAddr::V4(l.source), IpAddr::V4(l.destination), l.protocol));
            }
            Layer::Ipv6(l) => {
                addrs = Some((
                    IpAddr::V6(l.source),
                    IpAddr::V6(l.destination),
                    l.next_header,
                ));
            }
            Layer::Tcp(l) => {
                ports = Some((l.source_port, l.destination_port));
            }
            Layer::Udp(l) => {
                ports = Some((l.source_port, l.destination_port));
            }
            _ => {}
        }
    }

    let (src_addr, dst_addr, protocol) = addrs?;
    let (src_port, dst_port) = ports?;
    Some((src_addr, src_port, dst_addr, dst_port, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- StreamKey normalization tests ---

    #[test]
    fn stream_key_normalizes_direction() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let forward = StreamKey::new(a, 80, b, 12345, 6);
        let reverse = StreamKey::new(b, 12345, a, 80, 6);

        assert_eq!(forward, reverse);
    }

    #[test]
    fn stream_key_same_addr_different_ports_normalizes() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let forward = StreamKey::new(addr, 1000, addr, 2000, 6);
        let reverse = StreamKey::new(addr, 2000, addr, 1000, 6);

        assert_eq!(forward, reverse);
        assert_eq!(forward.port_lo, 1000);
        assert_eq!(forward.port_hi, 2000);
    }

    #[test]
    fn stream_key_different_protocols_differ() {
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let tcp = StreamKey::new(a, 80, b, 12345, 6);
        let udp = StreamKey::new(a, 80, b, 12345, 17);

        assert_ne!(tcp, udp);
    }

    #[test]
    fn stream_key_ipv6_normalizes() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let forward = StreamKey::new(a, 443, b, 51234, 6);
        let reverse = StreamKey::new(b, 51234, a, 443, 6);

        assert_eq!(forward, reverse);
    }

    #[test]
    fn stream_key_protocol_name() {
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        assert_eq!(StreamKey::new(a, 80, b, 1234, 6).protocol_name(), "TCP");
        assert_eq!(StreamKey::new(a, 53, b, 1234, 17).protocol_name(), "UDP");
        assert_eq!(StreamKey::new(a, 80, b, 1234, 1).protocol_name(), "Unknown");
    }

    // --- StreamTracker tests (no external dependencies) ---

    #[test]
    fn stream_tracker_get_returns_none_for_invalid_id() {
        let tracker = StreamTracker::new();
        assert!(tracker.get(0).is_none());
        assert!(tracker.get(999).is_none());
    }

    #[test]
    fn stream_tracker_default_is_empty() {
        let tracker = StreamTracker::default();
        assert_eq!(tracker.stream_count(), 0);
        assert!(tracker.streams().is_empty());
    }
}
