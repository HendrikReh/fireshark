mod support;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn has_tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn summary_json_outputs_valid_jsonl() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg("--json").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.is_empty(), "expected at least one JSON line");

    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
        assert!(value.get("index").is_some(), "missing 'index' field");
        assert!(value.get("protocol").is_some(), "missing 'protocol' field");
        assert!(value.get("source").is_some(), "missing 'source' field");
        assert!(
            value.get("destination").is_some(),
            "missing 'destination' field"
        );
        assert!(value.get("length").is_some(), "missing 'length' field");
        // stream_id may be null but should be present
        assert!(
            value.get("stream_id").is_some(),
            "missing 'stream_id' field"
        );
    }
}

#[test]
fn stats_json_outputs_single_object() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg("--json").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stats --json should output exactly one line"
    );

    let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(
        value.get("packet_count").is_some(),
        "missing 'packet_count' field"
    );
    assert!(
        value.get("stream_count").is_some(),
        "missing 'stream_count' field"
    );
    assert!(
        value.get("protocols").is_some(),
        "missing 'protocols' field"
    );
    assert!(
        value.get("top_endpoints").is_some(),
        "missing 'top_endpoints' field"
    );
}

#[test]
fn issues_json_outputs_jsonl() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues").arg("--json").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    // The fuzz fixture should produce at least one issue
    assert!(!stdout.is_empty(), "expected at least one JSON line");

    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
        assert!(
            value.get("packet_index").is_some(),
            "missing 'packet_index' field"
        );
        assert!(value.get("kind").is_some(), "missing 'kind' field");
        assert!(value.get("offset").is_some(), "missing 'offset' field");
    }
}

#[test]
fn audit_json_outputs_jsonl() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit").arg("--json").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    // The fuzz fixture may or may not produce findings, but output should be valid JSON
    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
        assert!(value.get("id").is_some(), "missing 'id' field");
        assert!(value.get("severity").is_some(), "missing 'severity' field");
        assert!(value.get("category").is_some(), "missing 'category' field");
        assert!(value.get("title").is_some(), "missing 'title' field");
        assert!(
            value.get("evidence_count").is_some(),
            "missing 'evidence_count' field"
        );
    }
}

#[test]
fn summary_json_suppresses_color() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg("--json").arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    // ANSI escape sequences start with ESC (0x1B)
    assert!(
        !stdout.contains('\x1b'),
        "JSON output should not contain ANSI escape sequences"
    );
}

#[test]
fn summary_json_with_filter() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("--json")
        .arg("-f")
        .arg("tcp")
        .arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
        assert_eq!(value["protocol"], "TCP");
    }
}

#[test]
fn summary_json_with_tshark_backend() {
    if !has_tshark() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary")
        .arg("--json")
        .arg("--backend")
        .arg("tshark")
        .arg(&fixture);
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.is_empty(), "expected at least one JSON line");

    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line: {e}\nline: {line}"));
        assert!(value.get("index").is_some());
        assert!(value.get("protocol").is_some());
        // tshark backend should have null stream_id
        assert!(value["stream_id"].is_null());
    }
}

#[test]
fn stats_json_no_human_text() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("stats").arg("--json").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("Capture Statistics").not())
        .stdout(predicates::str::contains("Protocol Distribution").not());
}

#[test]
fn issues_json_no_human_text() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("issues").arg("--json").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Decode Issues").not())
        .stdout(contains("issues in").not());
}

#[test]
fn audit_json_no_human_text() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("audit").arg("--json").arg(&fixture);
    cmd.assert()
        .success()
        .stdout(contains("Security Audit").not());
}
