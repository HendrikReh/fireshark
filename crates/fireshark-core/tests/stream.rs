use std::net::Ipv4Addr;
use std::time::Duration;

use fireshark_core::{
    DecodedFrame, EthernetLayer, Frame, Ipv4Layer, Layer, Packet, StreamTracker, TcpFlags, TcpLayer,
};
use fireshark_dissectors::decode_packet;

/// Helper: build a DecodedFrame from raw ethernet bytes.
fn decoded_from_bytes(bytes: &[u8]) -> DecodedFrame {
    let packet = decode_packet(bytes).unwrap();
    let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
    DecodedFrame::new(frame, packet)
}

/// Helper: build a DecodedFrame from raw bytes with a timestamp.
fn decoded_from_bytes_ts(bytes: &[u8], ts: Duration) -> DecodedFrame {
    let packet = decode_packet(bytes).unwrap();
    let frame = Frame::builder()
        .data(bytes.to_vec())
        .timestamp(ts)
        .build()
        .unwrap();
    DecodedFrame::new(frame, packet)
}

fn fixture(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut current = manifest_dir.to_path_buf();
    loop {
        if current.join("Cargo.toml").is_file()
            && current.join("crates").is_dir()
            && current.join("fixtures").is_dir()
        {
            return current.join("fixtures").join(name);
        }
        assert!(current.pop(), "workspace root should exist");
    }
}

#[test]
fn stream_tracker_assigns_same_id_for_both_directions() {
    let tcp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let decoded = decoded_from_bytes(&tcp_bytes);

    let mut tracker = StreamTracker::new();
    let id1 = tracker.assign(&decoded);
    let id2 = tracker.assign(&decoded);

    assert_eq!(id1, Some(0));
    assert_eq!(id2, Some(0));
    assert_eq!(tracker.stream_count(), 1);
}

#[test]
fn stream_tracker_assigns_different_ids_for_different_streams() {
    let tcp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let udp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_udp.bin")).unwrap();

    let tcp_decoded = decoded_from_bytes(&tcp_bytes);
    let udp_decoded = decoded_from_bytes(&udp_bytes);

    let mut tracker = StreamTracker::new();
    let tcp_id = tracker.assign(&tcp_decoded);
    let udp_id = tracker.assign(&udp_decoded);

    assert_eq!(tcp_id, Some(0));
    assert_eq!(udp_id, Some(1));
    assert_eq!(tracker.stream_count(), 2);
}

#[test]
fn stream_tracker_returns_none_for_non_transport_packets() {
    let arp_bytes = std::fs::read(fixture("bytes/ethernet_arp.bin")).unwrap();
    let decoded = decoded_from_bytes(&arp_bytes);

    let mut tracker = StreamTracker::new();
    let id = tracker.assign(&decoded);

    assert_eq!(id, None);
    assert_eq!(tracker.stream_count(), 0);
}

#[test]
fn stream_metadata_tracks_packet_count_and_bytes() {
    let tcp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let decoded = decoded_from_bytes(&tcp_bytes);

    let mut tracker = StreamTracker::new();
    tracker.assign(&decoded);
    tracker.assign(&decoded);
    tracker.assign(&decoded);

    let meta = tracker.get(0).unwrap();
    assert_eq!(meta.packet_count, 3);
    assert_eq!(meta.byte_count, tcp_bytes.len() * 3);
}

#[test]
fn stream_byte_count_uses_captured_len_not_original_len() {
    let tcp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_tcp.bin")).unwrap();
    let packet = decode_packet(&tcp_bytes).unwrap();
    // Build a frame where original_len > captured_len (simulating snaplen truncation)
    let frame = Frame::builder()
        .data(tcp_bytes.clone())
        .original_len(tcp_bytes.len() + 100)
        .build()
        .unwrap();
    let decoded = DecodedFrame::new(frame, packet);

    let mut tracker = StreamTracker::new();
    tracker.assign(&decoded);

    let meta = tracker.get(0).unwrap();
    // byte_count should use captured_len (tcp_bytes.len()), not original_len
    assert_eq!(meta.byte_count, tcp_bytes.len());
}

#[test]
fn stream_metadata_tracks_timestamps() {
    let tcp_bytes = std::fs::read(fixture("bytes/ethernet_ipv4_tcp.bin")).unwrap();

    let ts1 = Duration::from_millis(1000);
    let ts2 = Duration::from_millis(2000);
    let ts3 = Duration::from_millis(3000);

    let d1 = decoded_from_bytes_ts(&tcp_bytes, ts1);
    let d2 = decoded_from_bytes_ts(&tcp_bytes, ts2);
    let d3 = decoded_from_bytes_ts(&tcp_bytes, ts3);

    let mut tracker = StreamTracker::new();
    tracker.assign(&d1);
    tracker.assign(&d2);
    tracker.assign(&d3);

    let meta = tracker.get(0).unwrap();
    assert_eq!(meta.first_seen, Some(ts1));
    assert_eq!(meta.last_seen, Some(ts3));
}

/// Helper: build a DecodedFrame with specific TCP flags.
fn tcp_decoded_with_flags(flags: TcpFlags) -> DecodedFrame {
    let packet = Packet::new(
        vec![
            Layer::Ethernet(EthernetLayer {
                destination: [0, 1, 2, 3, 4, 5],
                source: [6, 7, 8, 9, 10, 11],
                ether_type: 0x0800,
            }),
            Layer::Ipv4(Ipv4Layer {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                protocol: 6,
                ttl: 64,
                identification: 0,
                dscp: 0,
                ecn: 0,
                dont_fragment: true,
                fragment_offset: 0,
                more_fragments: false,
                header_checksum: 0,
            }),
            Layer::Tcp(TcpLayer {
                source_port: 50_000,
                destination_port: 80,
                seq: 0,
                ack: 0,
                data_offset: 5,
                flags,
                window: 1024,
            }),
        ],
        Vec::new(),
    );
    let frame = Frame::builder()
        .captured_len(64)
        .data(vec![0; 64])
        .build()
        .unwrap();
    DecodedFrame::new(frame, packet)
}

fn default_flags() -> TcpFlags {
    TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    }
}

#[test]
fn stream_metadata_tracks_tcp_flags() {
    let syn_decoded = tcp_decoded_with_flags(TcpFlags {
        syn: true,
        ..default_flags()
    });
    let ack_decoded = tcp_decoded_with_flags(TcpFlags {
        ack: true,
        ..default_flags()
    });

    let mut tracker = StreamTracker::new();
    tracker.assign(&syn_decoded);
    tracker.assign(&ack_decoded);

    let meta = tracker.get(0).unwrap();
    // SYN = bit 1 (0x02), ACK = bit 4 (0x10)
    assert_eq!(meta.tcp_flags_seen & 0x02, 0x02, "SYN bit should be set");
    assert_eq!(meta.tcp_flags_seen & 0x10, 0x10, "ACK bit should be set");
}

#[test]
fn stream_metadata_counts_rst_packets() {
    let rst_decoded = tcp_decoded_with_flags(TcpFlags {
        rst: true,
        ..default_flags()
    });

    let mut tracker = StreamTracker::new();
    tracker.assign(&rst_decoded);
    tracker.assign(&rst_decoded);
    tracker.assign(&rst_decoded);

    let meta = tracker.get(0).unwrap();
    assert_eq!(meta.rst_count, 3);
}
