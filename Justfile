set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

summary file='fixtures/smoke/minimal.pcap':
    cargo run -p fireshark-cli -- summary {{file}}

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

check: fmt-check clippy test
