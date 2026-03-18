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
        .stdout(contains("Packets:"))
        .stdout(contains("Streams:"));
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

#[test]
fn stats_command_with_native_backend() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats")
        .arg("--backend")
        .arg("native")
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Capture Statistics"))
        .stdout(contains("TCP"));
}

#[test]
fn stats_command_with_tshark_backend() {
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
    cmd.arg("stats")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Capture Statistics"))
        .stdout(contains("TCP"));
}

#[test]
fn stats_command_excludes_undecodable_frames_from_packet_count() {
    let tmp = support::write_single_packet_pcap(&support::truncated_ethernet_packet());

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg(tmp.path());
    cmd.assert()
        .success()
        .stdout(contains("Packets:    0"))
        .stdout(contains("Streams:    0"))
        .stderr(contains("warning: packet 1: decode error"));
}
