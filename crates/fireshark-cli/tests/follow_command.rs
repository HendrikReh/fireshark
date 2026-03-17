mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn follow_command_shows_stream_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("follow").arg(&fixture).arg("0");
    cmd.assert()
        .success()
        .stdout(contains("Stream 0"))
        .stdout(contains("TCP"));
}

#[test]
fn follow_command_fails_for_invalid_stream() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("follow").arg(&fixture).arg("999");
    cmd.assert().failure();
}

#[test]
fn follow_command_rejects_tshark_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("follow")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture)
        .arg("0");
    cmd.assert()
        .failure()
        .stderr(contains("does not support the 'follow' command"));
}
