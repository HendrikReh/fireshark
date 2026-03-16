# PR #7 Review Fixes Plan

Consolidated from: Claude review + Codex review + design doc gap analysis.

## P1 — Blocking (must fix before merge)

### 1. Add capture size guard in `open_capture`
**Files:** `crates/fireshark-mcp/src/analysis.rs`, `crates/fireshark-mcp/src/tools.rs`
**Found by:** Claude + Codex (P1)
**Issue:** `AnalyzedCapture::open` eagerly decodes the entire capture into memory with no size/packet-count guard. The design doc explicitly requires "reject captures above a configured size threshold in v1 rather than degrading silently." A multi-GB capture will OOM the server.
**Fix:** Add a max packet count or max file size check before `collect()`. Return a `ToolError` if exceeded. Use a reasonable default (e.g., 100k packets) with a configurable constant.

### 2. Replace `expect()` with error return in `open_capture`
**File:** `crates/fireshark-mcp/src/tools.rs:57`
**Found by:** Claude
**Issue:** `expect("newly opened session should exist")` is reachable from user input. If the session manager implementation changes (e.g., concurrent access, session limit enforcement), this becomes a panic.
**Fix:** Replace with `.ok_or(ToolError::Session(SessionError::NotFound(...)))?`.

### 3. Add pagination to `search_packets`
**File:** `crates/fireshark-mcp/src/query.rs:44-49`, `crates/fireshark-mcp/src/server.rs`
**Found by:** Claude
**Issue:** `search_packets` returns all matching packets with no limit. A broad search on a large capture produces an unbounded JSON response.
**Fix:** Add `offset`/`limit` fields to `SearchPacketsRequest` (matching the pattern already used by `list_packets`). Default limit to something reasonable (e.g., 100).

## P2 — Should fix (significant improvements)

### 4. Add pagination to `list_decode_issues`
**File:** `crates/fireshark-mcp/src/query.rs:29-44`
**Found by:** Claude
**Issue:** A malformed capture can produce thousands of decode issues, all returned in one response.
**Fix:** Add `offset`/`limit` to the request type, matching `list_packets`.

### 5. Use `tokio::sync::Mutex` or `spawn_blocking`
**File:** `crates/fireshark-mcp/src/tools.rs` (all async methods)
**Found by:** Claude
**Issue:** All async tool methods acquire a `std::sync::Mutex` synchronously and hold it while iterating packets. This blocks the tokio runtime thread. Fine for single-client stdio v1, but will not scale.
**Fix:** Either switch to `tokio::sync::Mutex` or wrap lock-holding sections in `spawn_blocking`. Since v1 is single-client stdio, this can be deferred but should be done before adding concurrent transport.

### 6. Deduplicate `matches_filter`
**Files:** `crates/fireshark-mcp/src/query.rs:110`, `crates/fireshark-mcp/src/tools.rs:244`
**Found by:** Claude
**Issue:** `matches_filter` is duplicated in both files with the same logic.
**Fix:** Extract to a shared module (e.g., `filter.rs`) and import from both.

## P3 — Nice to have (low priority)

### 7. Bound memory for `audit_scan_activity` source_targets map
**File:** `crates/fireshark-mcp/src/audit.rs:27-42`
**Found by:** Claude
**Issue:** The `source_targets` map stores `Vec<usize>` of packet indexes per (source, destination) pair. For captures with millions of packets from one source, this grows large.
**Fix:** Consider capping the stored packet indexes (e.g., first N + total count) or using a count-only mode for large captures.

### 8. Session ID overflow protection
**File:** `crates/fireshark-mcp/src/session.rs:47-48`
**Found by:** Claude
**Issue:** `next_id` is a `u64` that increments forever. Overflow is practically impossible but IDs are never reclaimed from closed sessions.
**Fix:** No action needed for v1. Note for future if session churn becomes significant.

## Summary

| Priority | Count | Items |
|----------|-------|-------|
| P1 | 3 | Size guard, expect→error, search pagination |
| P2 | 3 | Issues pagination, async mutex, dedup filter |
| P3 | 2 | Audit memory bound, session ID overflow |
