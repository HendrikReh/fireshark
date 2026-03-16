use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn repo_has_expected_justfile_recipes() {
    let justfile = fs::read_to_string(repo_root().join("Justfile")).unwrap();

    assert!(justfile.contains("summary file='fixtures/smoke/minimal.pcap':"));
    assert!(justfile.contains("fmt:"));
    assert!(justfile.contains("fmt-check:"));
    assert!(justfile.contains("clippy:"));
    assert!(justfile.contains("test:"));
    assert!(justfile.contains("check: fmt-check clippy test"));
}

#[test]
fn readme_documents_just_first_workflow() {
    let readme = fs::read_to_string(repo_root().join("README.md")).unwrap();

    assert!(readme.contains("just summary"));
    assert!(readme.contains("just check"));
    assert!(readme.contains("cargo run -p fireshark-cli -- summary"));
    assert!(readme.contains("cargo run -p fireshark-mcp"));
    assert!(readme.contains("open_capture"));
    assert!(readme.contains("cargo fmt --all -- --check"));
    assert!(readme.contains("cargo test --workspace"));
}
