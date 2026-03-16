mod support;

use std::fs;

#[test]
fn repo_has_expected_justfile_recipes() {
    let justfile = fs::read_to_string(support::repo_root().join("Justfile")).unwrap();

    assert!(justfile.contains("summary file='fixtures/smoke/minimal.pcap':"));
    assert!(justfile.contains("fmt:"));
    assert!(justfile.contains("fmt-check:"));
    assert!(justfile.contains("clippy:"));
    assert!(justfile.contains("test:"));
    assert!(justfile.contains("check: fmt-check clippy test"));
}

#[test]
fn readme_documents_cli_and_development_workflow() {
    let readme = fs::read_to_string(support::repo_root().join("README.md")).unwrap();

    // CLI entry points — users need to find these
    assert!(
        readme.contains("fireshark-cli") || readme.contains("cargo run -p fireshark-cli"),
        "README should mention the CLI crate or how to run it"
    );
    assert!(
        readme.contains("just check") || readme.contains("just summary"),
        "README should mention just recipes"
    );

    // MCP server — key feature
    assert!(
        readme.contains("fireshark-mcp") || readme.contains("MCP"),
        "README should mention the MCP server"
    );

    // Development commands — developers need these
    assert!(
        readme.contains("cargo test") || readme.contains("just test"),
        "README should mention how to run tests"
    );
    assert!(
        readme.contains("cargo fmt") || readme.contains("just fmt"),
        "README should mention formatting"
    );
}

#[test]
fn crate_readme_contains_version_and_maintainer() {
    // Anchored from CARGO_MANIFEST_DIR so this works regardless of cwd
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(crate_dir.join("README.md")).unwrap();

    assert!(
        readme.contains("0.3.0"),
        "crate README should contain the current version"
    );
    assert!(
        readme.contains("blacksmith-consulting"),
        "crate README should contain the maintainer"
    );
}
