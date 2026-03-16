# CLI Color Output — Design Spec

## Purpose

Add Wireshark-style protocol coloring to the CLI `summary` command. Each packet row is colored based on its highest-layer protocol, making output instantly scannable by traffic type.

## Color Map

| Protocol | Color | Rationale |
|----------|-------|-----------|
| TCP | Green | Matches Wireshark convention for normal TCP traffic |
| UDP | Blue | Distinct from TCP, common traffic type |
| ARP | Yellow | Link-layer protocol, stands out as different |
| ICMP | Cyan | Diagnostic protocol, distinct hue |
| IPv4/IPv6 (no transport) | White | Network layer only, no further decode |
| Unknown / decode issues | Red | Signals something unusual worth investigating |

The color is determined by the protocol name string from `PacketSummary::protocol` — the same field already displayed in the output. The entire row gets that color, not just the protocol field.

## Dependencies

Add `colored = "3"` to `crates/fireshark-cli/Cargo.toml` under `[dependencies]`.

The `colored` crate provides:
- Automatic tty detection — colors suppressed when stdout is piped or redirected
- `NO_COLOR` environment variable support (see https://no-color.org/)
- Cross-platform terminal support including Windows 10+

No manual tty detection or `--no-color` flag needed.

## Changes

### New file: `crates/fireshark-cli/src/color.rs`

A single public function that maps a protocol name to a colored string:

```rust
pub fn colorize(protocol: &str, line: &str) -> ColoredString
```

The function matches `protocol` (case-insensitive) against the color map and returns the full line wrapped in the corresponding color. Unknown protocols or empty protocol strings map to red.

### Modified file: `crates/fireshark-cli/src/summary.rs`

Update the print loop to:
1. Format the summary line as a plain `String` (same format as today)
2. Pass through `colorize(&summary.protocol, &line)` before printing

### Modified file: `crates/fireshark-cli/src/main.rs`

Add `mod color;` to register the new module.

### No changes to other crates

`fireshark-core`, `fireshark-dissectors`, `fireshark-file`, and `fireshark-mcp` are not touched.

## Testing

The existing CLI integration test (`summary_command_prints_one_packet_row`) uses `assert_cmd` which captures stdout. The `colored` crate detects this as a non-tty and suppresses ANSI codes, so the test continues to pass without changes.

Add a unit test in `color.rs` that verifies the `colorize` function returns a string containing ANSI escape sequences for known protocols. Use `colored::control::set_override(true)` to force color output in the test environment regardless of tty detection.

## Out of Scope

- Packet detail view (Spec 2)
- Hex dump (Spec 2)
- Display filter language (Spec 3)
- Configurable color themes
- Per-field coloring (field-based color strategy was rejected in brainstorming)
