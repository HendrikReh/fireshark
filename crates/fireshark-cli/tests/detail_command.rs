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
fn detail_command_handles_fuzz_fixture_without_panic() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    // Packet 12 in the fuzz fixture has decode issues (Unknown protocol)
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("12");
    cmd.assert()
        .success()
        .stdout(contains("Hex Dump"))
        .stdout(contains("0000"));
}

#[test]
fn detail_command_renders_decode_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    // Packet 4 is ARP — exercises a different layer path through detail
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("detail").arg(&fixture).arg("4");
    cmd.assert()
        .success()
        .stdout(contains("Ethernet"))
        .stdout(contains("ARP"));
}
