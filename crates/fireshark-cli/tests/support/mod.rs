use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    fireshark_core::find_workspace_root(manifest_dir)
        .expect("workspace root should exist above CARGO_MANIFEST_DIR")
}

#[allow(dead_code)]
pub fn write_single_packet_pcap(packet: &[u8]) -> tempfile::NamedTempFile {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, // magic, version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // thiszone, sigfigs
        0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen, ethernet
    ]);

    let pkt_len = packet.len() as u32;
    pcap.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(packet);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &pcap).unwrap();
    tmp
}

#[allow(dead_code)]
pub fn truncated_ethernet_packet() -> Vec<u8> {
    vec![0u8; 10]
}
