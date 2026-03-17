use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut current = manifest_dir.to_path_buf();

    loop {
        if current.join("Cargo.toml").is_file()
            && current.join("crates").is_dir()
            && current.join("fixtures").is_dir()
        {
            return current;
        }

        assert!(current.pop(), "workspace root should exist");
    }
}
