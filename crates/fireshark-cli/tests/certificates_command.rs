mod support;

use assert_cmd::Command;

fn tshark_available() -> bool {
    fireshark_tshark::is_available()
}

#[test]
fn certificates_command_runs_without_tshark_error_message() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("certificates").arg(&fixture);
    // minimal.pcap has no TLS, so should report "No TLS certificates found."
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No TLS certificates"));
}

#[test]
fn certificates_json_outputs_empty_for_no_tls() {
    if !tshark_available() {
        eprintln!("skipping: tshark not available");
        return;
    }
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("certificates").arg(&fixture).arg("--json");
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    // No TLS traffic → no output lines
    assert!(stdout.is_empty());
}
