use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    let current_dir = std::env::current_dir().expect("current directory should be available");
    find_workspace_root(&current_dir).expect("workspace root should exist")
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
