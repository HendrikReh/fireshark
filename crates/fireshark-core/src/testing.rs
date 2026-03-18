use std::path::{Path, PathBuf};

/// Walk upward from `start` to locate the workspace root directory.
///
/// The workspace root is identified by the presence of `Cargo.toml`, `crates/`,
/// `fixtures/`, and `Justfile`. Call this from test support modules with
/// `env!("CARGO_MANIFEST_DIR")` as the starting path.
pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if current.join("Cargo.toml").is_file()
            && current.join("crates").is_dir()
            && current.join("fixtures").is_dir()
            && current.join("Justfile").is_file()
        {
            return Some(current);
        }

        if !current.pop() {
            return None;
        }
    }
}
