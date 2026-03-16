mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn summary_command_prints_one_packet_row() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("TCP"))
        .stdout(contains("T00:")) // ISO 8601 time separator
        .stdout(contains("Z")); // UTC suffix
}
