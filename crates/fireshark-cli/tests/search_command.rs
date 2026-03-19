mod support;

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn search_by_protocol_filters_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("search").arg(&fixture).arg("--protocol").arg("TCP");
    cmd.assert().success().stdout(contains("TCP"));
}

#[test]
fn search_by_port_filters_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("search").arg(&fixture).arg("--port").arg("443");
    cmd.assert().success().stdout(contains("443"));
}

#[test]
fn search_with_no_criteria_shows_all() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("search").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    // Should show at least one packet
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.is_empty());
}

#[test]
fn search_json_outputs_valid_jsonl() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("search").arg(&fixture).arg("--json");
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    for line in stdout.lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn search_has_issues_filters_to_problematic_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    // minimal.pcap has clean packets, so --has-issues should show nothing
    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("search").arg(&fixture).arg("--has-issues");
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.is_empty());
}
