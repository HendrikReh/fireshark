mod support;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fireshark_core::find_workspace_root;
use support::repo_root;

#[test]
fn repo_root_finds_the_current_workspace() {
    let root = repo_root();

    assert!(root.join("Justfile").is_file());
    assert!(root.join("fixtures/smoke/minimal.pcap").is_file());
}

#[test]
fn finds_workspace_root_from_nested_crate_directory() {
    let root = temp_test_dir();
    fs::create_dir_all(root.join("crates")).unwrap();
    fs::create_dir_all(root.join("crates/fireshark-cli")).unwrap();
    fs::create_dir_all(root.join("fixtures/smoke")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(root.join("Justfile"), "summary:\n").unwrap();

    let nested_crate_dir = root.join("crates/fireshark-cli");
    let found = find_workspace_root(&nested_crate_dir).unwrap();

    assert_eq!(found, root);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn returns_none_when_workspace_markers_are_missing() {
    let root = temp_test_dir();
    fs::create_dir_all(root.join("crates/fireshark-cli")).unwrap();

    let nested_crate_dir = root.join("crates/fireshark-cli");
    let found = find_workspace_root(&nested_crate_dir);

    assert!(found.is_none());

    fs::remove_dir_all(root).unwrap();
}

fn temp_test_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fireshark-runtime-paths-{unique}-{}",
        std::process::id(),
    ))
}
