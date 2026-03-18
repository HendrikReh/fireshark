# Clone Hot Paths Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the approved clone hot paths in filter evaluation and backend aggregation while preserving current behavior.

**Architecture:** Keep the change narrow. `fireshark-filter` will borrow string field data through internal evaluation helpers, and `fireshark-backend` will aggregate counts from borrowed packet summaries after packet construction so repeated values do not allocate per packet.

**Tech Stack:** Rust 2024 workspace, cargo test, cargo clippy, internal crate unit tests and integration tests.

---

### Task 1: Add failing filter regression

**Files:**
- Modify: `crates/fireshark-filter/src/fields.rs`

**Steps:**
1. Add a unit test that resolves an HTTP or DNS string field and asserts the returned string reuses the underlying packet storage.
2. Run the focused filter test to verify it fails under the current owned-`String` implementation.

### Task 2: Implement borrowed filter string handling

**Files:**
- Modify: `crates/fireshark-filter/src/fields.rs`
- Modify: `crates/fireshark-filter/src/evaluate.rs`

**Steps:**
1. Make `FieldValue` borrow string data instead of owning it.
2. Update evaluation helpers to work with borrowed strings.
3. Re-run the focused filter test.
4. Re-run the full `fireshark-filter` test suite.

### Task 3: Add failing backend aggregation regression

**Files:**
- Modify: `crates/fireshark-backend/src/capture.rs`

**Steps:**
1. Add a focused test that exercises the new packet-summary aggregation helper.
2. Run the focused backend test to verify it fails before the helper exists.

### Task 4: Refactor backend aggregation

**Files:**
- Modify: `crates/fireshark-backend/src/capture.rs`
- Modify: `crates/fireshark-backend/src/native.rs`
- Modify: `crates/fireshark-backend/src/tshark.rs`

**Steps:**
1. Build packets first.
2. Aggregate counts from borrowed packet summaries.
3. Keep sorting and external output unchanged.
4. Re-run the focused backend test.
5. Re-run the full `fireshark-backend` test suite.

### Task 5: Verify and land

**Files:**
- Modify: `docs/plans/2026-03-18-clone-hotpaths-design.md`
- Modify: `docs/plans/2026-03-18-clone-hotpaths.md`

**Steps:**
1. Run the targeted crate tests for `fireshark-filter` and `fireshark-backend`.
2. Run `cargo test --workspace --quiet`.
3. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
4. Review the diff carefully against unrelated worktree changes.
5. Commit the scoped changes, run `bd sync`, pull/rebase if needed, and push.
