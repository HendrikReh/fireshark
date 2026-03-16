use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    // Anchor from CARGO_MANIFEST_DIR (set by cargo at compile time) rather than
    // the ambient current working directory, making tests hermetic under
    // alternate runners and IDEs.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    find_workspace_root(manifest_dir).expect("workspace root should exist above CARGO_MANIFEST_DIR")
}

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
