use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn fireshark_mcp_binary_starts() {
    let mut cmd = Command::cargo_bin("fireshark-mcp").unwrap();
    cmd.arg("--help");
    cmd.assert().success().stdout(contains("fireshark-mcp"));
}
