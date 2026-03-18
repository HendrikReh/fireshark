# Fireshark DevOps / CI Guide

## Build Pipeline

The project uses [`just`](https://github.com/casey/just) as its task runner. The single gate command that must pass before any merge is:

```bash
just check
```

This runs three stages sequentially -- if any stage fails, the pipeline stops:

1. **Format check** -- `cargo fmt --all -- --check`
2. **Clippy lint** -- `cargo clippy --workspace --all-targets -- -D warnings`
3. **Test suite** -- `cargo test --workspace`

## Verification Commands

| Command | What it does | When to use |
|---------|-------------|-------------|
| `just fmt` | `cargo fmt --all` | Auto-format before committing |
| `just fmt-check` | `cargo fmt --all -- --check` | CI gate: fail if unformatted |
| `just clippy` | `cargo clippy --workspace --all-targets -- -D warnings` | CI gate: all warnings are errors |
| `just test` | `cargo test --workspace` | CI gate: run all 437 tests |
| `just check` | All three above in sequence | Full CI gate |

### Raw Commands (Without `just`)

If `just` is not available in the CI environment, use these directly:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Fuzz Testing

Fireshark includes a `cargo-fuzz` setup with two fuzz targets. Fuzzing requires the nightly Rust toolchain.

### Fuzz Targets

| Target | What it fuzzes | Input |
|--------|---------------|-------|
| `fuzz_decode_packet` | Full dissector chain (`decode_packet`) | Raw bytes treated as an Ethernet frame |
| `fuzz_capture_reader` | Capture file reader (`CaptureReader::open`) | Raw bytes treated as a pcap/pcapng file |

### Running Fuzz Tests Locally

```bash
cd fuzz
cargo +nightly fuzz run fuzz_decode_packet -- -max_total_time=60
cargo +nightly fuzz run fuzz_capture_reader -- -max_total_time=60
```

### CI Integration

For CI, run each fuzz target with a bounded time limit:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_decode_packet -- -max_total_time=120
cargo +nightly fuzz run fuzz_capture_reader -- -max_total_time=120
```

Fuzz findings are written to `fuzz/artifacts/<target>/`. If a crash is found:

1. The artifact file in `fuzz/artifacts/` reproduces the crash
2. Copy the artifact to `fixtures/smoke/` or `fixtures/bytes/` as a regression test
3. Fix the bug and add a test that uses the artifact via `include_bytes!`

### Fuzz Dependencies

The fuzz crate (`fuzz/Cargo.toml`) depends on:

- `libfuzzer-sys` 0.4
- `fireshark-dissectors` (path dependency)
- `fireshark-file` (path dependency)
- `tempfile` 3 (for writing fuzz input to disk for the capture reader target)

## Release Checklist

### 1. Version Bump

Update the version in the workspace root and all crate manifests. The workspace version is defined in one place:

```toml
# Cargo.toml (workspace root)
[workspace.package]
version = "X.Y.Z"
```

Each crate also has its own `version` field that must match:

- `Cargo.toml` (workspace)
- `crates/fireshark-core/Cargo.toml`
- `crates/fireshark-dissectors/Cargo.toml`
- `crates/fireshark-file/Cargo.toml`
- `crates/fireshark-filter/Cargo.toml`
- `crates/fireshark-cli/Cargo.toml`
- `crates/fireshark-mcp/Cargo.toml`
- `crates/fireshark-backend/Cargo.toml`
- `crates/fireshark-tshark/Cargo.toml`

### 2. Update Badges

Update the version badge in `README.md`:

```markdown
[![Version](https://img.shields.io/badge/version-X.Y.Z-blue)]()
```

Update the test count badge if the test count has changed:

```markdown
[![Tests](https://img.shields.io/badge/tests-NNN%20passing-brightgreen)]()
```

### 3. Update Footer

Update the `Last updated` date and version in the footer of:

- `README.md`
- `crates/fireshark-mcp/README.md`
- `crates/fireshark-filter/README.md`
- Any other documents with the standard footer

### 4. Verify

```bash
just check
```

### 5. Tag

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

## Dependencies

Fireshark follows a minimal-dependency philosophy. External crates are used only when they provide substantial value over hand-written code.

### Runtime Dependencies

| Crate | Version | Used by | Purpose |
|-------|---------|---------|---------|
| `thiserror` | 2.0.17 | dissectors, file, filter, mcp | Derive macros for error types |
| `pcap-file` | 3.0.0-rc1 | fireshark-file | pcap and pcapng file parsing |
| `regex` | 1 | fireshark-filter | Regular expression matching for `matches` string operator |
| `clap` | 4.6.0 | fireshark-cli | CLI argument parsing with derive |
| `colored` | 3 | fireshark-cli | Terminal color output |
| `rmcp` | 0.16 | fireshark-mcp | MCP protocol implementation |
| `schemars` | 1 | fireshark-mcp | JSON Schema generation for MCP tool parameters |
| `serde` | 1 | fireshark-mcp | Serialization for MCP request/response types |
| `serde_json` | 1 | fireshark-mcp | JSON serialization |
| `tokio` | 1 | fireshark-mcp | Async runtime for MCP server |

### Dev / Test Dependencies

| Crate | Version | Used by | Purpose |
|-------|---------|---------|---------|
| `assert_cmd` | 2.1.1 | fireshark-cli, fireshark-mcp | CLI integration testing |
| `predicates` | 3.1.3 | fireshark-cli, fireshark-mcp | Assertion helpers for CLI output |
| `tempfile` | 3 | fireshark-cli, fuzz | Temporary file creation in tests |

### Fuzz Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `libfuzzer-sys` | 0.4 | libFuzzer integration for cargo-fuzz |
| `tempfile` | 3 | Write fuzz input to disk for capture reader target |

### Zero-Dependency Crates

`fireshark-core` has no external runtime dependencies (only workspace path dependencies). `fireshark-filter` depends on `regex` (added in v0.7 for the `matches` string operator).

## Tooling Requirements

| Tool | Version | Required for | Notes |
|------|---------|-------------|-------|
| Rust toolchain | 1.85+ | Everything | Edition 2024 requires 1.85 minimum |
| `cargo` | (ships with Rust) | Everything | Build, test, clippy, fmt |
| `just` | Any recent | Task running | Optional -- raw cargo commands work too |
| `cargo-fuzz` | Any recent | Fuzz testing only | Requires nightly Rust toolchain |
| Nightly Rust | Latest | Fuzz testing only | `rustup toolchain install nightly` |
| `tshark` | 3.0.0+ | tshark backend only | Optional — from Wireshark, searched in PATH and known locations |

### CI Environment Setup

```bash
# Install stable Rust (for build, test, clippy, fmt)
rustup install stable
rustup default stable

# Install nightly Rust (for fuzz testing only)
rustup install nightly

# Install just
cargo install just

# Install cargo-fuzz (optional, for fuzz CI)
cargo +nightly install cargo-fuzz
```

## Workspace Structure

```
fireshark/
  Cargo.toml              # Workspace root
  Justfile                 # Task runner recipes
  crates/
    fireshark-core/        # Domain types (no external deps)
    fireshark-dissectors/  # Protocol decoders
    fireshark-file/        # Capture file readers
    fireshark-filter/      # Display filter language
    fireshark-cli/         # CLI binary
    fireshark-mcp/         # MCP server binary
    fireshark-backend/     # Backend abstraction (native + tshark)
    fireshark-tshark/      # tshark subprocess adapter
  fixtures/
    bytes/                 # 18 handcrafted protocol binary fixtures
    smoke/                 # 3 small capture files for integration tests
  fuzz/
    fuzz_targets/          # 2 fuzz target binaries
    Cargo.toml             # Separate workspace for fuzz crate
```

---

**Version:** 0.8.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
