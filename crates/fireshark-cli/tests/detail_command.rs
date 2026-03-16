mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn detail_command_shows_layer_tree_and_hex() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("1");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("IPv4"))
        .stdout(contains("TCP"))
        .stdout(contains("51514"))
        .stdout(contains("443"))
        .stdout(contains("[SYN]"))
        .stdout(contains("0000"))
        .stdout(contains("Hex Dump"));
}

#[test]
fn detail_command_fails_for_out_of_range_packet() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("999");
    cmd.assert().failure();
}

#[test]
fn detail_command_fails_for_zero_packet_number() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("0");
    cmd.assert().failure();
}

#[test]
fn detail_command_works_with_pcapng() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcapng");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("1");
    cmd.assert().success().stdout(contains("Ethernet"));
}

#[test]
fn detail_command_renders_unknown_ethertype() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    // Packet 12 has unknown EtherType 0x6d00 — only Ethernet layer decoded
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("12");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("Unknown"))
        .stdout(contains("Hex Dump"))
        .stdout(contains("0000"));
}

#[test]
fn detail_command_renders_arp_layer() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    // Packet 4 is ARP — exercises a different layer path through detail
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("4");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("ARP"));
}

#[test]
fn detail_command_renders_decode_issues() {
    // Create a fixture inline: valid Ethernet + IPv4 header claiming total_len=100
    // but only 20 bytes of IPv4 present — triggers a truncation decode issue
    // Then write to a temp pcap and run detail on it
    // Build a minimal pcap with a truncated IPv4 packet
    let mut pcap = Vec::new();
    // pcap global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (ethernet)
    pcap.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, // magic (little endian)
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0x00, 0x00, 0x00, 0x00, // thiszone
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen
        0x01, 0x00, 0x00, 0x00, // network (ethernet)
    ]);
    // Packet: Ethernet (14) + IPv4 header (20) claiming total_len=100 but only 20 bytes
    let mut pkt = Vec::new();
    // Ethernet header
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src
    pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header: version=4, IHL=5, TOS=0, total_len=100 (truncated!)
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x64]); // ver+ihl, tos, total_len=100
    pkt.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]); // id, flags+offset (DF)
    pkt.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // ttl=64, proto=TCP, checksum
    pkt.extend_from_slice(&[0xc0, 0x00, 0x02, 0x0a]); // src 192.0.2.10
    pkt.extend_from_slice(&[0xc6, 0x33, 0x64, 0x14]); // dst 198.51.100.20
    // No TCP payload — IPv4 claims 100 bytes but only 20 are here
    let pkt_len = pkt.len() as u32;
    // pcap packet header: ts_sec=1, ts_usec=0, incl_len, orig_len
    pcap.extend_from_slice(&1u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(&pkt);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    std::fs::write(&path, &pcap).unwrap();

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&path).arg("1");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("IPv4"))
        .stdout(contains("Truncated"));
}
