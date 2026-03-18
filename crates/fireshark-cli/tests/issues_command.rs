mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn issues_command_shows_decode_issues() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Decode Issues"))
        .stdout(contains("issues in"));
}

#[test]
fn issues_command_works_with_clean_pcap() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Decode Issues"))
        .stdout(contains("issues in"));
}

#[test]
fn issues_command_rejects_tshark_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture);
    cmd.assert()
        .failure()
        .stderr(contains("requires the native backend"));
}

#[test]
fn issues_command_excludes_undecodable_frames_from_packet_totals() {
    let tmp = support::write_single_packet_pcap(&support::truncated_ethernet_packet());

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues").arg(tmp.path());
    cmd.assert()
        .success()
        .stdout(contains("0 issues in 0 packets"))
        .stderr(contains("warning: packet 1: decode error"));
}
