# v0.6 Features — Design Spec

## Purpose

Three features for v0.6 (Security Analyst Platform): JSON export for CLI commands, IPv4/TCP/UDP checksum validation, and capture comparison. Each is independent and can ship incrementally.

## Feature 1: JSON Export (`--json` flag)

### Scope

Add `--json` flag to 4 CLI commands: `summary`, `stats`, `issues`, `audit`. When set, output is JSONL (one JSON object per line) with no ANSI color codes or formatting.

MCP already returns JSON — no MCP changes needed.

### Dependencies

Add `serde = { version = "1", features = ["derive"] }` and `serde_json = "1"` to `fireshark-cli/Cargo.toml`.

### CLI changes

Add `--json` flag to `Summary`, `Stats`, `Issues`, `Audit` command variants in `main.rs`:

```rust
#[arg(long = "json", help = "Output as JSONL (one JSON object per line)")]
json: bool,
```

### JSON schemas

**summary** (one line per packet):
```json
{"index":1,"timestamp":"2005-07-04T09:32:20.839Z","protocol":"TCP","source":"192.168.1.2:51514","destination":"198.51.100.20:443","length":54,"stream_id":0}
```

`stream_id` is `null` when not tracked (tshark backend) or when the packet has no transport layer.

**stats** (single JSON object):
```json
{"packet_count":691,"stream_count":244,"duration_seconds":1566.5,"first_timestamp":"2005-07-04T09:32:20.839Z","last_timestamp":"2005-07-04T09:58:27.427Z","protocols":[{"name":"UDP","count":580,"percent":83.9}],"top_endpoints":[{"endpoint":"192.168.1.2","count":412}]}
```

**issues** (one line per issue):
```json
{"packet_index":45,"kind":"Malformed","offset":14}
```

**audit** (one line per finding):
```json
{"id":"scan-activity-10.0.0.1","severity":"high","category":"scan_activity","title":"Endpoint fan-out from 10.0.0.1 looks scan-like","evidence_count":47}
```

### Implementation

Each command module (`summary.rs`, `stats.rs`, `issues.rs`, `audit.rs`) gets an `if json { ... } else { ... }` branch. The JSON branch constructs a `serde::Serialize` struct and prints it with `serde_json::to_string`.

Define serializable structs in a new `crates/fireshark-cli/src/json.rs` module:

```rust
#[derive(Serialize)]
pub struct PacketJson { pub index: usize, pub timestamp: Option<String>, pub protocol: String, pub source: String, pub destination: String, pub length: usize, pub stream_id: Option<u32> }

#[derive(Serialize)]
pub struct StatsJson { pub packet_count: usize, pub stream_count: usize, ... }

#[derive(Serialize)]
pub struct IssueJson { pub packet_index: usize, pub kind: String, pub offset: usize }

#[derive(Serialize)]
pub struct FindingJson { pub id: String, pub severity: String, pub category: String, pub title: String, pub evidence_count: usize }
```

### Testing

- `summary --json` on minimal.pcap: assert output is valid JSON, contains expected fields
- `stats --json`: assert single JSON object with packet_count
- `issues --json` on fuzz fixture: assert JSONL with Malformed/Truncated
- `audit --json` on fuzz fixture: assert JSONL with finding IDs
- Verify `--json` suppresses color codes (no ANSI escapes in output)

## Feature 2: Checksum Validation (issue #8)

### Scope

Validate IPv4 header checksum, TCP checksum, and UDP checksum. Report mismatches as a new `DecodeIssueKind::ChecksumMismatch` variant.

### New DecodeIssueKind variant

In `crates/fireshark-core/src/issues.rs`:

```rust
pub enum DecodeIssueKind {
    Truncated,
    Malformed,
    ChecksumMismatch,
}
```

Add `DecodeIssue::checksum_mismatch(offset: usize)` constructor.

### IPv4 header checksum

In `crates/fireshark-dissectors/src/ipv4.rs`:

After parsing all fields, compute the ones' complement sum over the header bytes (`bytes[0..header_len]`). If the result is not `0xFFFF` (or equivalently, if the computed checksum doesn't match `header_checksum`), push a `DecodeIssue::checksum_mismatch` to the issues vec.

Skip validation when `header_checksum == 0` (some implementations leave it zero).

The checksum algorithm:
```rust
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
```

A valid header has `ipv4_checksum(header_bytes) == 0` (the checksum field is included in the computation).

### TCP checksum

In `crates/fireshark-dissectors/src/tcp.rs`:

TCP checksum requires a pseudo-header: source IP (4 bytes), destination IP (4 bytes), zero byte, protocol (1 byte = 6), TCP segment length (2 bytes). This means `tcp::parse` needs the IP addresses and total TCP length passed to it.

**Signature change:** `tcp::parse(bytes, offset)` → `tcp::parse(bytes, offset, checksum_context: Option<ChecksumContext>)` where:

```rust
pub struct ChecksumContext {
    pub src_ip: [u8; 4],  // or 16 for IPv6
    pub dst_ip: [u8; 4],
    pub protocol: u8,
    pub segment_len: u16,
}
```

Actually, this is a significant change to the dissector pattern. Simpler approach: **validate checksums in the orchestrator (`lib.rs`) after both IP and transport layers are parsed**, since the orchestrator has access to both. This avoids changing any dissector signatures.

Add a `validate_transport_checksum` function in `lib.rs` that:
1. Extracts IP addresses from the IPv4/IPv6 layer
2. Extracts the transport payload from the network payload
3. Computes the TCP/UDP checksum including pseudo-header
4. Compares with the checksum from the raw bytes
5. Pushes `DecodeIssue::checksum_mismatch` if mismatched

### UDP checksum

Same pseudo-header pattern as TCP. Skip validation when `checksum == 0` (explicitly optional in IPv4 per RFC 768).

### NIC offload note

Many captures are taken after NIC checksum offload, where the NIC hasn't computed the checksum yet so the value is zero or garbage. Document this in the CLI `--help` and in the detail view when a mismatch is reported.

### Testing

- Existing fixtures have `checksum: 0` — these should NOT produce mismatch issues
- Create a fixture with a deliberately wrong IPv4 checksum → verify `ChecksumMismatch` issue
- Create a fixture with correct checksums → verify no issues
- Test the `ipv4_checksum` function directly with known header bytes

## Feature 3: Capture Comparison

### Scope

New CLI command `fireshark diff <file1> <file2>` and MCP tool `compare_captures(session_a, session_b)`. Compares two captures at the summary level.

### Comparison output

```
Capture Comparison
──────────────────────────────────────
  File A: traffic-morning.pcap  (450 packets, 32 streams)
  File B: traffic-evening.pcap  (680 packets, 51 streams)

  Packet delta:   +230
  Stream delta:   +19

  New hosts in B (not in A):
    10.0.0.50       45 packets
    10.0.0.51       12 packets

  Missing hosts from A (not in B):
    10.0.0.30       28 packets

  New protocols in B:
    TLS             89 packets

  New ports in B:
    8443            34 packets
```

With `--json`, output as a single JSON object:
```json
{"file_a":{"path":"...","packet_count":450,"stream_count":32},"file_b":{"path":"...","packet_count":680,"stream_count":51},"new_hosts":[{"host":"10.0.0.50","count":45}],"missing_hosts":[{"host":"10.0.0.30","count":28}],"new_protocols":[{"name":"TLS","count":89}],"new_ports":[{"port":8443,"count":34}]}
```

### Implementation

Use `BackendCapture` for both files — works with native and tshark backends.

CLI: `crates/fireshark-cli/src/diff.rs`
MCP: `compare_captures(session_id_a, session_id_b)` tool in `server.rs`

The comparison logic lives in `fireshark-backend` as a shared function since both CLI and MCP need it:

```rust
pub fn compare(a: &BackendCapture, b: &BackendCapture) -> CaptureComparison
```

### CaptureComparison type

In `crates/fireshark-backend/src/compare.rs`:

```rust
pub struct CaptureComparison {
    pub a_packet_count: usize,
    pub b_packet_count: usize,
    pub a_stream_count: usize,
    pub b_stream_count: usize,
    pub new_hosts: Vec<(String, usize)>,
    pub missing_hosts: Vec<(String, usize)>,
    pub new_protocols: Vec<(String, usize)>,
    pub new_ports: Vec<(u16, usize)>,
}
```

"New" means present in B but not A. "Missing" means present in A but not B. Hosts are IP addresses extracted from endpoint counts. Ports extracted from packet summaries.

### MCP tool

```rust
#[tool(description = "Compare two capture sessions and identify differences")]
async fn compare_captures(&self, Parameters(request): Parameters<CompareCapturesRequest>) -> McpResult<CaptureComparisonView>
```

### Testing

- Compare minimal.pcap with itself → no differences
- Compare minimal.pcap with fuzz fixture → differences in hosts, protocols, packet count
- `diff --json` → valid JSON output

## Modified Files

### JSON export
- `crates/fireshark-cli/Cargo.toml` — add serde, serde_json
- `crates/fireshark-cli/src/json.rs` — new module with serializable types
- `crates/fireshark-cli/src/main.rs` — `--json` flag on 4 commands
- `crates/fireshark-cli/src/summary.rs` — JSON branch
- `crates/fireshark-cli/src/stats.rs` — JSON branch
- `crates/fireshark-cli/src/issues.rs` — JSON branch
- `crates/fireshark-cli/src/audit.rs` — JSON branch

### Checksum validation
- `crates/fireshark-core/src/issues.rs` — `ChecksumMismatch` variant
- `crates/fireshark-dissectors/src/lib.rs` — `validate_transport_checksum` function
- `crates/fireshark-dissectors/src/ipv4.rs` — IPv4 header checksum validation
- `crates/fireshark-cli/src/detail.rs` — render ChecksumMismatch
- `crates/fireshark-mcp/src/model.rs` — format_issue_kind for ChecksumMismatch

### Capture comparison
- `crates/fireshark-backend/src/compare.rs` — comparison logic
- `crates/fireshark-backend/src/lib.rs` — export
- `crates/fireshark-cli/src/diff.rs` — diff command
- `crates/fireshark-cli/src/main.rs` — diff command variant
- `crates/fireshark-mcp/src/server.rs` — compare_captures tool
- `crates/fireshark-mcp/src/tools.rs` — handler
- `crates/fireshark-mcp/src/model.rs` — CaptureComparisonView

## Out of Scope

- Certificate parsing (requires TCP reassembly — deferred to v0.7+)
- ICMP checksum validation (low priority)
- Checksum correction/recalculation
- Capture merge (combining two captures into one)
- Byte-level diff between individual packets
