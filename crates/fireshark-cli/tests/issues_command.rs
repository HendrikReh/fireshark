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
