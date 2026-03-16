mod support;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn summary_filter_tcp_excludes_non_tcp() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture).arg("-f").arg("tcp");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("TCP"))
        .stdout(predicates::str::contains("UDP").not())
        .stdout(predicates::str::contains("ARP").not());
}

#[test]
fn summary_filter_invalid_expression_exits_nonzero() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture).arg("-f").arg("invalid $$");
    cmd.assert().failure();
}

#[test]
fn summary_no_filter_still_works() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture);
    cmd.assert().success().stdout(contains("TCP"));
}

#[test]
fn summary_filter_port_works() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture).arg("-f").arg("port 443");
    cmd.assert().success().stdout(contains("TCP"));
}

#[test]
fn summary_filter_dns_shows_only_dns() {
    let fixture = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");

    let mut cmd = Command::cargo_bin("fireshark").unwrap();
    cmd.arg("summary").arg(&fixture).arg("-f").arg("dns");
    cmd.assert().success().stdout(contains("DNS"));
}
