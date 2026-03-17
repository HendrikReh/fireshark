mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn audit_command_shows_findings() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit").arg(&fixture);
    cmd.assert().success().stdout(contains("Security Audit"));
}

#[test]
fn audit_command_works_with_minimal_pcap() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit").arg(&fixture);
    cmd.assert().success().stdout(contains("Security Audit"));
}

#[test]
fn audit_command_rejects_tshark_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture);
    cmd.assert()
        .failure()
        .stderr(contains("does not support the 'audit' command"));
}
