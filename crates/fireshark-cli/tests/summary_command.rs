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

#[test]
fn summary_command_works_with_pcapng() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcapng");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture);
    cmd.assert().success().stdout(contains("TCP"));
}

#[test]
fn summary_command_with_native_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("--backend")
        .arg("native")
        .arg(&fixture);
    cmd.assert().success().stdout(contains("TCP"));
}

#[test]
fn summary_command_with_tshark_backend() {
    if std::process::Command::new("tshark")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture);
    cmd.assert().success().stdout(contains("TCP"));
}
