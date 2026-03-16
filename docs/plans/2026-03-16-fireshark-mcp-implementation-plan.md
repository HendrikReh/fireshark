# Fireshark MCP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an offline, stateful MCP server that lets an LLM open `.pcap` and `.pcapng` files once, inspect decoded packets, and run basic security-audit workflows against the decoded capture.

**Architecture:** Add a new `fireshark-mcp` crate that depends directly on `fireshark-file`, `fireshark-dissectors`, and `fireshark-core`. Keep the MCP transport, session lifecycle, JSON-facing models, and audit heuristics in that crate; keep packet parsing and decoding in the existing crates. Use the official Rust MCP SDK (`rmcp`) over stdio and keep v1 focused on tools, not resources or prompts.

**Tech Stack:** Rust 2024 workspace, `rmcp` over stdio, `tokio`, `serde`, `serde_json`, `thiserror`, existing Fireshark crates, fixture-backed tests, and `cargo test` / `cargo fmt --all -- --check` / `cargo clippy --workspace --all-targets -- -D warnings`.

---

## Task 1: Add The MCP Crate Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/fireshark-mcp/Cargo.toml`
- Create: `crates/fireshark-mcp/src/lib.rs`
- Create: `crates/fireshark-mcp/src/main.rs`
- Create: `crates/fireshark-mcp/src/server.rs`
- Create: `crates/fireshark-mcp/tests/server_help.rs`

**Step 1: Create a failing smoke test for the new binary**

```rust
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn fireshark_mcp_binary_starts() {
    let mut cmd = Command::cargo_bin("fireshark-mcp").unwrap();
    cmd.arg("--help");
    cmd.assert().success().stdout(contains("fireshark-mcp"));
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-mcp --test server_help -- --nocapture`
Expected: FAIL because the crate and binary do not exist yet

**Step 3: Add the workspace member and minimal crate**

```toml
[package]
name = "fireshark-mcp"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "fireshark-mcp"
path = "src/main.rs"

[dependencies]
rmcp = "0.16"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "io-std"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2.0.17"
fireshark-core = { path = "../fireshark-core" }
fireshark-dissectors = { path = "../fireshark-dissectors" }
fireshark-file = { path = "../fireshark-file" }

[dev-dependencies]
assert_cmd = "2.1.1"
predicates = "3.1.3"
```

```rust
// src/main.rs
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fireshark_mcp::server::run_stdio().await
}
```

**Step 4: Re-run the smoke test**

Run: `cargo test -p fireshark-mcp --test server_help -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add Cargo.toml crates/fireshark-mcp
git commit -m "feat: add fireshark MCP crate skeleton"
```

## Task 2: Build Runtime Capture Analysis

**Files:**
- Modify: `crates/fireshark-mcp/src/lib.rs`
- Create: `crates/fireshark-mcp/src/analysis.rs`
- Create: `crates/fireshark-mcp/src/model.rs`
- Create: `crates/fireshark-mcp/tests/open_capture.rs`

**Step 1: Write a failing analysis test around the smoke fixture**

```rust
use fireshark_mcp::analysis::AnalyzedCapture;

#[test]
fn open_capture_decodes_minimal_fixture() {
    let capture = AnalyzedCapture::open("fixtures/smoke/minimal.pcap").unwrap();
    assert_eq!(capture.packet_count(), 1);
    assert_eq!(capture.protocol_counts().get("TCP"), Some(&1));
}
```

**Step 2: Run the test to verify it fails**

Run: `cargo test -p fireshark-mcp --test open_capture open_capture_decodes_minimal_fixture -- --exact`
Expected: FAIL because `AnalyzedCapture` does not exist

**Step 3: Implement the analysis model**

```rust
pub struct AnalyzedCapture {
    packets: Vec<fireshark_core::DecodedFrame>,
    protocol_counts: BTreeMap<String, usize>,
    endpoint_counts: BTreeMap<String, usize>,
}

impl AnalyzedCapture {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AnalysisError> {
        let reader = fireshark_file::CaptureReader::open(path)?;
        let packets = fireshark_core::Pipeline::new(reader, fireshark_dissectors::decode_packet)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_packets(packets))
    }
}
```

**Step 4: Re-run the test**

Run: `cargo test -p fireshark-mcp --test open_capture open_capture_decodes_minimal_fixture -- --exact`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add analyzed capture model"
```

## Task 3: Add Stateful Session Management

**Files:**
- Modify: `crates/fireshark-mcp/src/lib.rs`
- Create: `crates/fireshark-mcp/src/session.rs`
- Create: `crates/fireshark-mcp/tests/session_manager.rs`

**Step 1: Write failing lifecycle tests**

```rust
use fireshark_mcp::session::SessionManager;

#[test]
fn open_and_close_session_round_trip() {
    let mut sessions = SessionManager::new(8);
    let id = sessions.open_path("fixtures/smoke/minimal.pcap").unwrap();
    assert!(sessions.get(&id).is_some());
    sessions.close(&id).unwrap();
    assert!(sessions.get(&id).is_none());
}
```

**Step 2: Run the lifecycle tests**

Run: `cargo test -p fireshark-mcp --test session_manager -- --nocapture`
Expected: FAIL because `SessionManager` does not exist

**Step 3: Implement a minimal session store**

```rust
pub struct SessionManager {
    next_id: u64,
    max_sessions: usize,
    sessions: BTreeMap<String, CaptureSession>,
}

pub struct CaptureSession {
    pub id: String,
    pub capture: AnalyzedCapture,
    pub last_accessed: Instant,
}
```

**Step 4: Add one expiry test before implementing idle cleanup**

```rust
#[test]
fn expired_sessions_are_rejected() {
    // construct, age, expire, assert missing
}
```

**Step 5: Re-run the tests**

Run: `cargo test -p fireshark-mcp --test session_manager -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add MCP session manager"
```

## Task 4: Add Low-Level Query APIs

**Files:**
- Modify: `crates/fireshark-mcp/src/model.rs`
- Create: `crates/fireshark-mcp/src/query.rs`
- Create: `crates/fireshark-mcp/tests/query.rs`

**Step 1: Write a failing packet-list test**

```rust
use fireshark_mcp::analysis::AnalyzedCapture;
use fireshark_mcp::query::list_packets;

#[test]
fn list_packets_returns_packet_summaries() {
    let capture = AnalyzedCapture::open("fixtures/smoke/minimal.pcap").unwrap();
    let packets = list_packets(&capture, 0, 10, None, None);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
}
```

**Step 2: Run the query test to verify it fails**

Run: `cargo test -p fireshark-mcp --test query list_packets_returns_packet_summaries -- --exact`
Expected: FAIL because `list_packets` does not exist

**Step 3: Implement JSON-facing packet/query models**

```rust
#[derive(Debug, Clone, Serialize)]
pub struct PacketSummaryView {
    pub index: usize,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub length: usize,
    pub has_issues: bool,
}
```

**Step 4: Add a failing `get_packet` test and implement the matching detail view**

```rust
#[test]
fn get_packet_returns_layers_and_issues() {
    // open minimal fixture, fetch index 0, assert layers are non-empty
}
```

**Step 5: Re-run the query tests**

Run: `cargo test -p fireshark-mcp --test query -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add low-level packet query APIs"
```

## Task 5: Add Audit Findings And Heuristics

**Files:**
- Create: `crates/fireshark-mcp/src/audit.rs`
- Create: `crates/fireshark-mcp/tests/audit.rs`

**Step 1: Write a failing synthetic audit test**

```rust
use fireshark_core::{DecodeIssue, DecodeIssueKind, Layer, Packet};
use fireshark_mcp::audit::AuditEngine;

#[test]
fn audit_flags_decode_issue_heavy_capture() {
    // build a small synthetic analyzed capture with decode issues
    // assert at least one finding in category "decode_issues"
}
```

**Step 2: Run the audit tests**

Run: `cargo test -p fireshark-mcp --test audit -- --nocapture`
Expected: FAIL because `AuditEngine` does not exist

**Step 3: Implement explicit finding models**

```rust
#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<FindingEvidenceView>,
}
```

**Step 4: Implement the first heuristics only**

- decode issue concentration
- unknown/undecoded traffic concentration
- scan-like endpoint fan-out
- suspicious port usage indicators

Do not add payload inspection, stream analysis, or signature engines.

**Step 5: Re-run the audit tests**

Run: `cargo test -p fireshark-mcp --test audit -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add MCP audit heuristics"
```

## Task 6: Add MCP Tool Handlers

**Files:**
- Create: `crates/fireshark-mcp/src/tools.rs`
- Modify: `crates/fireshark-mcp/src/lib.rs`
- Create: `crates/fireshark-mcp/tests/tools.rs`

**Step 1: Write a failing tool-handler test without transport**

```rust
use fireshark_mcp::tools::ToolService;

#[tokio::test]
async fn open_capture_tool_returns_session_metadata() {
    let service = ToolService::new_default();
    let result = service.open_capture("fixtures/smoke/minimal.pcap").await.unwrap();
    assert_eq!(result.packet_count, 1);
}
```

**Step 2: Run the tool-handler tests**

Run: `cargo test -p fireshark-mcp --test tools -- --nocapture`
Expected: FAIL because `ToolService` does not exist

**Step 3: Implement tool-call wrappers around the domain APIs**

```rust
pub struct ToolService {
    sessions: Arc<Mutex<SessionManager>>,
}
```

Tool coverage for v1:
- `open_capture`
- `describe_capture`
- `close_capture`
- `list_packets`
- `get_packet`
- `list_decode_issues`
- `summarize_protocols`
- `top_endpoints`
- `search_packets`
- `audit_capture`
- `list_findings`
- `explain_finding`

**Step 4: Re-run the tool-handler tests**

Run: `cargo test -p fireshark-mcp --test tools -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add MCP tool handlers"
```

## Task 7: Wire The stdio MCP Server

**Files:**
- Modify: `crates/fireshark-mcp/src/server.rs`
- Modify: `crates/fireshark-mcp/src/main.rs`
- Create: `crates/fireshark-mcp/tests/stdio_smoke.rs`

**Step 1: Write a failing stdio integration test**

```rust
#[tokio::test]
async fn stdio_server_handles_open_capture_tool() {
    // spawn `cargo run -p fireshark-mcp`
    // send an MCP initialize handshake
    // call `open_capture`
    // assert a session_id comes back
}
```

**Step 2: Run the integration test**

Run: `cargo test -p fireshark-mcp --test stdio_smoke -- --nocapture`
Expected: FAIL because the stdio MCP transport is not wired yet

**Step 3: Implement `rmcp` server wiring**

```rust
pub async fn run_stdio() -> Result<(), Box<dyn std::error::Error>> {
    // build ToolService
    // register tool schemas
    // serve over stdio transport
    Ok(())
}
```

**Step 4: Re-run the stdio integration test**

Run: `cargo test -p fireshark-mcp --test stdio_smoke -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/fireshark-mcp
git commit -m "feat: add stdio MCP server"
```

## Task 8: Document MCP Usage

**Files:**
- Modify: `README.md`
- Create: `docs/reports/2026-03-16-fireshark-mcp-smoke-test.md`

**Step 1: Write a failing docs test or assertion if needed**

If you extend existing docs assertions, add the smallest README check that mentions `fireshark-mcp`.

**Step 2: Document the server**

Add:
- what the server does
- that v1 is offline-only
- how to run it over stdio
- the v1 tool families
- that sessions are ephemeral and host-local

**Step 3: Record one manual smoke-test transcript**

Write a short report that captures:
- startup command
- open-capture request
- one packet query
- one audit request

**Step 4: Run docs verification**

Run: `cargo test -p fireshark-cli --test justfile_docs -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add README.md docs/reports
git commit -m "docs: add MCP server usage notes"
```

## Final Verification

Run these commands after Task 8:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`

Expected: all commands pass with zero failures.
