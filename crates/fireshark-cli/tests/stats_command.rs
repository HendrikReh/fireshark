mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn stats_command_shows_protocol_distribution() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Capture Statistics"))
        .stdout(contains("Protocol Distribution"))
        .stdout(contains("Packets:"));
}

#[test]
fn stats_command_works_with_minimal_pcap() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Capture Statistics"))
        .stdout(contains("TCP"))
        .stdout(contains("Top Endpoints"));
}
