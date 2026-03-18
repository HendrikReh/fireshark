mod support;

use assert_cmd::Command;

#[test]
fn diff_identical_captures_shows_no_differences() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff").arg(&fixture).arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Capture Comparison"));
    assert!(stdout.contains("Packet delta:   +0"));
    assert!(stdout.contains("Stream delta:   +0"));
    // Identical captures should not show any new/missing hosts or protocols
    assert!(!stdout.contains("New hosts"));
    assert!(!stdout.contains("Missing hosts"));
    assert!(!stdout.contains("New protocols"));
    assert!(!stdout.contains("New ports"));
}

#[test]
fn diff_different_captures_shows_changes() {
    let fixture_a = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let fixture_b = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff").arg(&fixture_a).arg(&fixture_b);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Capture Comparison"));
    // The two captures differ in packet count, so we should see a nonzero delta
    assert!(!stdout.contains("Packet delta:   +0"));
}

#[test]
fn diff_json_outputs_valid_json() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff").arg("--json").arg(&fixture).arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "diff --json should output exactly one line");

    let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(value.get("file_a").is_some(), "missing 'file_a' field");
    assert!(value.get("file_b").is_some(), "missing 'file_b' field");
    assert!(
        value.get("new_hosts").is_some(),
        "missing 'new_hosts' field"
    );
    assert!(
        value.get("missing_hosts").is_some(),
        "missing 'missing_hosts' field"
    );
    assert!(
        value.get("new_protocols").is_some(),
        "missing 'new_protocols' field"
    );
    assert!(
        value.get("new_ports").is_some(),
        "missing 'new_ports' field"
    );
}

#[test]
fn diff_json_identical_captures_empty_diffs() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff").arg("--json").arg(&fixture).arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(
        value["new_hosts"].as_array().unwrap().len(),
        0,
        "identical captures should have no new hosts"
    );
    assert_eq!(
        value["missing_hosts"].as_array().unwrap().len(),
        0,
        "identical captures should have no missing hosts"
    );
    assert_eq!(
        value["new_protocols"].as_array().unwrap().len(),
        0,
        "identical captures should have no new protocols"
    );
    assert_eq!(
        value["new_ports"].as_array().unwrap().len(),
        0,
        "identical captures should have no new ports"
    );
}

#[test]
fn diff_json_different_captures_shows_differences() {
    let fixture_a = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let fixture_b = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff")
        .arg("--json")
        .arg(&fixture_a)
        .arg(&fixture_b);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    // File metadata should be present
    assert!(value["file_a"]["packet_count"].as_u64().unwrap() > 0);
    assert!(value["file_b"]["packet_count"].as_u64().unwrap() > 0);
}

#[test]
fn diff_reports_native_stream_counts() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("diff").arg("--json").arg(&fixture).arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(value["file_a"]["stream_count"], 1);
    assert_eq!(value["file_b"]["stream_count"], 1);
}
