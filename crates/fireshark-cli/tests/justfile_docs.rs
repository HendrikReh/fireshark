use std::fs;

#[test]
fn crate_readme_documents_cli_and_development_workflow() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(crate_dir.join("README.md")).unwrap();

    // CLI entry points — users need to find these
    assert!(
        readme.contains("fireshark-cli") || readme.contains("fireshark detail"),
        "crate README should mention the CLI crate or how to run it"
    );
    assert!(
        readme.contains("summary") && readme.contains("detail"),
        "crate README should describe the CLI subcommands"
    );

    // Development commands — developers need these
    assert!(
        readme.contains("summary.rs")
            && readme.contains("detail.rs")
            && readme.contains("hexdump.rs"),
        "crate README should document the main CLI modules"
    );
    assert!(
        readme.contains("color output") || readme.contains("hex dump"),
        "crate README should describe the main user-facing output behavior"
    );
}

#[test]
fn crate_readme_contains_version_and_maintainer() {
    // Anchored from CARGO_MANIFEST_DIR so this works regardless of cwd
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(crate_dir.join("README.md")).unwrap();

    assert!(
        readme.contains("0.5.2"),
        "crate README should contain the current version"
    );
    assert!(
        readme.contains("blacksmith-consulting"),
        "crate README should contain the maintainer"
    );
}
