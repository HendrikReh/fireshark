# fireshark-tshark

tshark subprocess backend for fireshark capture analysis.

## Overview

Discovers and executes the `tshark` command-line tool (from Wireshark) to analyze capture files. Parses machine-readable output and normalizes it into fireshark's backend-neutral model.

## Requirements

- `tshark` version 3.0.0 or later (from Wireshark)
- Available in PATH or at known locations (`/Applications/Wireshark.app/Contents/MacOS/tshark`)

## Key Types

- **`TsharkVersion`** -- parsed tshark version (major.minor.patch)
- **`TsharkError`** -- errors from tshark discovery, execution, or output parsing

## Discovery

The `discover()` function searches for tshark:
1. `tshark` in PATH
2. `/Applications/Wireshark.app/Contents/MacOS/tshark` (macOS)
3. `/usr/local/bin/tshark`
4. `/usr/bin/tshark`

Validates the version is >= 3.0.0 (JSON/fields output format requirement).

## Execution

Uses `tshark -T fields` with tab-separated output for reliable parsing. Extracts: frame number, timestamp, length, protocol, source/destination addresses, ports.

No JSON dependency -- TSV parsing is simple and version-stable.

---

**Version:** 0.5.2 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
