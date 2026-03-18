use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    fireshark_core::find_workspace_root(manifest_dir)
        .expect("workspace root should exist above CARGO_MANIFEST_DIR")
}
