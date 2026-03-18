# fireshark-fuzz

Standalone `cargo-fuzz` workspace for exercising the fireshark parser stack with arbitrary input.

This directory is intentionally separate from the main workspace in the repository root. Normal commands such as `cargo test --workspace` and `cargo clippy --workspace` stay focused on the publishable crates under `crates/`, while fuzzing remains opt-in and can use the nightly toolchain and `cargo-fuzz` without affecting the default developer loop.

## Prerequisites

- Rust nightly toolchain
- `cargo-fuzz`

Install them once:

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
```

## Layout

- `Cargo.toml` - standalone fuzz workspace and target definitions
- `fuzz_targets/fuzz_decode_packet.rs` - fuzzes `fireshark_dissectors::decode_packet`
- `fuzz_targets/fuzz_capture_reader.rs` - fuzzes `fireshark_file::CaptureReader::open`

## Running the Targets

From the repository root:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_decode_packet -- -max_total_time=60
cargo +nightly fuzz run fuzz_capture_reader -- -max_total_time=60
```

What each target does:

- `fuzz_decode_packet` feeds arbitrary bytes into the full dissector entrypoint and asserts that malformed input does not panic.
- `fuzz_capture_reader` writes arbitrary bytes to a temporary file, opens it through the capture reader, and iterates any returned frames without panicking.

## Crash Artifacts and Regression Tests

When a target crashes, `cargo-fuzz` writes a reproducer under `fuzz/artifacts/<target>/`.

Re-run a saved artifact with:

```bash
cd fuzz
cargo +nightly fuzz run <target> artifacts/<target>/<artifact-file>
```

After reproducing a crash:

1. Reduce the artifact if possible.
2. Copy the reproducer into `fixtures/bytes/` or `fixtures/smoke/`.
3. Add a regression test in the relevant crate so the bug stays covered by the normal test suite.

## Notes

- This package is `publish = false`.
- The harness depends on `libfuzzer-sys`, `tempfile`, `fireshark-dissectors`, and `fireshark-file`.
- The main workspace root intentionally does not include `fuzz/` as a member.

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
