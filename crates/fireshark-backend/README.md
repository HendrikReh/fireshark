# fireshark-backend

Shared backend abstraction for fireshark capture analysis.

## Overview

Provides a backend-neutral capture model that both CLI and MCP can consume. Two backend implementations: native (Rust pipeline) and tshark (subprocess). Supports capture comparison to identify new/missing hosts, protocols, and ports between two captures.

## Key Types

- **`BackendKind`** -- `Native` or `Tshark`, parsed from strings
- **`BackendCapture`** -- backend-neutral analyzed capture with packets, protocol counts, endpoint counts
- **`BackendPacket`** -- single packet with summary, layers, and issues
- **`BackendCapabilities`** -- what the active backend supports (streams, filters, audit, etc.)
- **`BackendError`** -- errors from backend operations

## Usage

```rust
use fireshark_backend::{BackendCapture, BackendKind};

let capture = BackendCapture::open("capture.pcap", BackendKind::Native)?;
println!("{} packets", capture.packet_count());

// Or with tshark (requires tshark installed):
let capture = BackendCapture::open("capture.pcap", BackendKind::Tshark)?;
```

## Backends

### Native (default)
Wraps the existing Rust pipeline (`fireshark-file` + `fireshark-dissectors` + `fireshark-core`). Full feature support: streams, filters, audit, layer spans.

### Tshark (optional)
Runs `tshark -T fields` as a subprocess and normalizes the output. Provides instant coverage of all Wireshark-supported protocols. Limited capabilities: no streams, no native filter, no audit, no layer spans.

## Capability Model

Each backend declares its capabilities. Consumers check before using features:

| Capability | Native | Tshark |
|-----------|--------|--------|
| Streams | Yes | No |
| Decode issues | Yes | No |
| Native filter | Yes | No |
| Layer spans | Yes | No |
| Audit | Yes | No |

---

**Version:** 0.5.2 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
