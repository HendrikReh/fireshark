# Clone Hot Paths Design

**Date:** 2026-03-18

**Goal:** Remove the two approved clone hot paths without changing external behavior: string-field filter evaluation in `fireshark-filter`, and per-packet summary string cloning in backend packet aggregation.

## Scope

This pass is intentionally limited to:

1. Borrow string field data through filter evaluation instead of cloning it into temporary owned `String` values.
2. Build backend count summaries from borrowed packet data after packet construction instead of cloning protocol/source/destination strings while ingesting every packet.

This pass does **not** include the low-priority MCP session-id cleanup.

## Options Considered

### Option 1: Minimal ownership refactor, no public API changes

- Change internal `FieldValue` string handling from owned `String` to borrowed string slices.
- Keep the public filter API unchanged.
- Refactor backend aggregation into a helper that counts from borrowed packet summaries.

**Pros:** Targets the hot paths directly, keeps surface area small, easy to validate with existing tests plus focused regressions.

**Cons:** Requires threading lifetimes through internal filter helpers.

### Option 2: Shared string/interning layer

- Introduce shared interned strings or `Arc<str>` for summaries and filter fields.

**Pros:** Could reduce allocations more broadly.

**Cons:** Much larger design change, wider API impact, not justified for this narrow pass.

### Option 3: Leave code structure as-is and rely on profiling only

- Keep current code and only document the hot paths.

**Pros:** No code churn.

**Cons:** Leaves the reviewed allocation hotspots in place.

## Selected Approach

Use Option 1.

For `fireshark-filter`, make `FieldValue` lifetime-parameterized and borrow packet-owned string data for DNS/TLS/HTTP fields. Comparison helpers will operate on `&str` directly and only allocate when a string representation is genuinely required for non-string fallback comparisons.

For `fireshark-backend`, construct `BackendPacket` values first, then derive protocol and endpoint counts from borrowed packet summaries. The aggregation helper will count repeated values without cloning per packet and only allocate when producing the final owned `(String, usize)` result vectors.

## Testing Strategy

- Add a focused unit test in `fireshark-filter` that proves resolved string fields borrow the underlying packet storage rather than allocate new owned strings.
- Add focused backend tests around the aggregation helper so the refactor is driven by tests before production code changes.
- Re-run the targeted crate tests, then workspace-level tests and clippy.
