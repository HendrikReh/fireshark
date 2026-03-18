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
fn detail_command_renders_malformed_decode_issue() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    // Packet 45 has a malformed IPv4 header (version != 4) — triggers ⚠ Malformed
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("45");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("Malformed"));
}

#[test]
fn detail_command_renders_truncated_decode_issue() {
    // Inline pcap: valid Ethernet + IPv4 claiming total_len=100 but only 20 bytes
    // present — triggers ⚠ Truncated for the missing TCP payload
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, // magic, version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // thiszone, sigfigs
        0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen, ethernet
    ]);
    let pkt: Vec<u8> = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // eth dst
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // eth src
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x00, 0x64, // ver+ihl, tos, total_len=100 (truncated!)
        0x00, 0x01, 0x40, 0x00, // id, flags+offset
        0x40, 0x06, 0x00, 0x00, // ttl, proto=TCP, checksum
        0xc0, 0x00, 0x02, 0x0a, // src
        0xc6, 0x33, 0x64, 0x14, // dst
    ]
    .to_vec();
    let pkt_len = pkt.len() as u32;
    pcap.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(&pkt_len.to_le_bytes());
    pcap.extend_from_slice(&pkt);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &pcap).unwrap();

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(tmp.path()).arg("1");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("IPv4"))
        .stdout(contains("Truncated"));
}

#[test]
fn detail_command_renders_dns_layer() {
    let fixture = support::repo_root().join("fixtures/smoke/wireshark-dns.pcap");

    // Packet 1 should be a DNS query — verify DNS layer fields are rendered
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("1");
    cmd.assert()
        .success()
        .stdout(contains("DNS"))
        .stdout(contains("Transaction ID"))
        .stdout(contains("Query"));
}

#[test]
fn detail_command_rejects_tshark_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture)
        .arg("1");
    cmd.assert()
        .failure()
        .stderr(contains("requires the native backend"));
}
