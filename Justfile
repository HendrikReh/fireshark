set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

summary file='fixtures/smoke/minimal.pcap':
    cargo run -p fireshark-cli -- summary {{file}}

fmt:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

check: fmt clippy test
