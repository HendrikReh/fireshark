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
        .stderr(contains("requires the native backend"));
}

#[test]
fn audit_command_with_security_profile_succeeds() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit")
        .arg("--profile")
        .arg("security")
        .arg(&fixture);
    cmd.assert().success().stdout(contains("Security Audit"));
}

#[test]
fn audit_command_with_quality_profile_succeeds() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit")
        .arg("--profile")
        .arg("quality")
        .arg(&fixture);
    cmd.assert().success().stdout(contains("Security Audit"));
}

#[test]
fn audit_command_with_dns_profile_succeeds() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit").arg("--profile").arg("dns").arg(&fixture);
    cmd.assert().success().stdout(contains("Security Audit"));
}

#[test]
fn audit_command_with_invalid_profile_fails() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit")
        .arg("--profile")
        .arg("invalid")
        .arg(&fixture);
    cmd.assert()
        .failure()
        .stderr(contains("unknown audit profile"));
}
