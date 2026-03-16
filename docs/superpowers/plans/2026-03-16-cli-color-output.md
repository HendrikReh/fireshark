# CLI Color Output Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Wireshark-style protocol coloring to the CLI summary command using the `colored` crate.

**Architecture:** A new `color.rs` module in `fireshark-cli` maps protocol names to ANSI colors. The summary print loop formats lines as plain strings, then colorizes the entire row based on the protocol. The `colored` crate handles tty detection and `NO_COLOR` automatically.

**Tech Stack:** Rust, `colored` crate v3.

**Spec:** `docs/superpowers/specs/2026-03-16-cli-color-output-design.md`

---

## Chunk 1: Implementation

### Task 1: Add colored dependency

**Files:**
- Modify: `crates/fireshark-cli/Cargo.toml`

- [ ] **Step 1: Add colored to dependencies**

In `crates/fireshark-cli/Cargo.toml`, add `colored` to `[dependencies]`:

```toml
[dependencies]
clap = { version = "4.6.0", features = ["derive"] }
colored = "3"
fireshark-core = { path = "../fireshark-core" }
fireshark-dissectors = { path = "../fireshark-dissectors" }
fireshark-file = { path = "../fireshark-file" }
```

- [ ] **Step 2: Verify it resolves**

Run: `cargo check -p fireshark-cli`
Expected: PASS

### Task 2: Create color module with tests

**Files:**
- Create: `crates/fireshark-cli/src/color.rs`
- Modify: `crates/fireshark-cli/src/main.rs`

- [ ] **Step 1: Create color.rs with colorize function and tests**

Create `crates/fireshark-cli/src/color.rs`:

```rust
use colored::{ColoredString, Colorize};

/// Colorize an entire summary line based on the protocol name.
///
/// Color map (Wireshark-inspired):
/// - TCP → green
/// - UDP → blue
/// - ARP → yellow
/// - ICMP → cyan
/// - IPv4/IPv6 → white
/// - Unknown/other → red
pub fn colorize(protocol: &str, line: &str) -> ColoredString {
    match protocol.to_ascii_uppercase().as_str() {
        "TCP" => line.green(),
        "UDP" => line.blue(),
        "ARP" => line.yellow(),
        "ICMP" => line.cyan(),
        "IPV4" | "IPV6" => line.white(),
        _ => line.red(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn force_color<F: FnOnce()>(f: F) {
        colored::control::set_override(true);
        f();
        colored::control::unset_override();
    }

    #[test]
    fn tcp_lines_are_green() {
        force_color(|| {
            let output = colorize("TCP", "test line").to_string();
            assert!(output.contains("\x1b[32m"), "TCP should be green (ANSI 32)");
            assert!(output.contains("test line"));
        });
    }

    #[test]
    fn udp_lines_are_blue() {
        force_color(|| {
            let output = colorize("UDP", "test line").to_string();
            assert!(output.contains("\x1b[34m"), "UDP should be blue (ANSI 34)");
        });
    }

    #[test]
    fn arp_lines_are_yellow() {
        force_color(|| {
            let output = colorize("ARP", "test line").to_string();
            assert!(output.contains("\x1b[33m"), "ARP should be yellow (ANSI 33)");
        });
    }

    #[test]
    fn icmp_lines_are_cyan() {
        force_color(|| {
            let output = colorize("ICMP", "test line").to_string();
            assert!(output.contains("\x1b[36m"), "ICMP should be cyan (ANSI 36)");
        });
    }

    #[test]
    fn ipv4_lines_are_white() {
        force_color(|| {
            let output = colorize("IPv4", "test line").to_string();
            assert!(output.contains("\x1b[37m"), "IPv4 should be white (ANSI 37)");
        });
    }

    #[test]
    fn unknown_protocol_is_red() {
        force_color(|| {
            let output = colorize("Unknown", "test line").to_string();
            assert!(output.contains("\x1b[31m"), "Unknown should be red (ANSI 31)");
        });
    }

    #[test]
    fn colorize_is_case_insensitive() {
        force_color(|| {
            let lower = colorize("tcp", "line").to_string();
            let upper = colorize("TCP", "line").to_string();
            assert_eq!(lower, upper);
        });
    }
}
```

- [ ] **Step 2: Register the module in main.rs**

In `crates/fireshark-cli/src/main.rs`, replace the module declarations with (adding `mod color;` in alphabetical order):

```rust
mod color;
mod summary;
mod timestamp;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p fireshark-cli color`
Expected: PASS — 7 tests

### Task 3: Integrate colorize into summary output

**Files:**
- Modify: `crates/fireshark-cli/src/summary.rs`

- [ ] **Step 1: Update summary.rs to use colorize**

Replace the contents of `crates/fireshark-cli/src/summary.rs`:

```rust
use std::path::Path;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = decoded?;
        let summary = decoded.summary();
        let ts = match summary.timestamp {
            Some(duration) => timestamp::format_utc(duration),
            None => String::from("-"),
        };
        let line = format!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            index + 1,
            ts,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}
```

- [ ] **Step 2: Run all CLI tests**

Run: `cargo test -p fireshark-cli`
Expected: PASS — all existing tests plus the 7 new color tests

- [ ] **Step 3: Smoke test with real output**

Run: `cargo run -p fireshark-cli -- summary fixtures/smoke/fuzz-2006-06-26-2594.pcap 2>/dev/null | head -15`
Expected: Colored output — UDP lines in blue, ARP in yellow, Unknown in red. (If piped, colors are suppressed by the colored crate, so run without pipe to see colors.)

- [ ] **Step 4: Run just check**

Run: `just check`
Expected: PASS — fmt, clippy, all tests

- [ ] **Step 5: Commit**

```bash
git add crates/fireshark-cli/Cargo.toml crates/fireshark-cli/src/color.rs \
       crates/fireshark-cli/src/main.rs crates/fireshark-cli/src/summary.rs
git commit -m "feat: add Wireshark-style protocol coloring to CLI summary"
```
