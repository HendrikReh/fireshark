# Fireshark PR Review Skill — Design Spec

## Purpose

A project-specific PR review skill that checks fireshark code changes against two domains: **security/robustness** (critical for a packet parser handling untrusted input) and **architecture compliance** (dissector patterns, layer separation, error handling conventions).

## Behavior

### Diff Scope (auto-detect)

- If on a feature branch (not `master`): diff all commits against `master` (`git diff master...HEAD`)
- If on `master`: review staged + unstaged changes (`git diff HEAD`)

### Execution Model

- Dispatches a **subagent** with the diff and a fireshark-specific review checklist
- Subagent returns structured findings grouped by severity
- Keeps review output out of main conversation context

### Invocation

- **Claude-invoked**: triggers automatically after completing implementation work
- **User-invoked**: manually via `/fireshark-pr-review`
- Frontmatter: both `user-invocable` and model-invocable (default)

## Review Checklist

### Security & Robustness

| Check | Rationale |
|---|---|
| No `unwrap()`/`expect()` on packet-derived data | Panics on untrusted input = denial of service |
| Explicit bounds check before every slice access | Out-of-bounds = panic or memory safety issue |
| Integer overflow protection in length/offset arithmetic | Attacker-controlled lengths can wrap |
| `DecodeError::Truncated` for short buffers | Consistent error classification |
| `DecodeError::Malformed` for invalid field values | Consistent error classification |
| No panic paths reachable from untrusted input | All malformed packets must produce `Err`, never panic |

### Architecture Compliance

| Check | Rationale |
|---|---|
| Dissector modules follow pattern: constants → `parse()` → bounds-first validation | Consistency across all protocol decoders |
| Network-layer dissectors return `NetworkPayload` | Carries payload slice + offset for transport decoding |
| Link/transport-layer dissectors return `Layer` | Simpler contract, no payload forwarding |
| New `Layer` variants added to enum and `name()` match | Exhaustive match ensures no missed cases |
| Errors use `thiserror` with existing `DecodeError` variants | No ad hoc error types |
| File parsing stays separate from protocol dissection | Core architectural boundary |
| Tests use `include_bytes!` with fixtures from `fixtures/bytes/` | Fixture-based testing convention |
| New protocols have tests for valid decode, truncation, and malformation | Minimum test coverage for any dissector |

## Output Format

Findings grouped by severity:

```
## Blocking (must fix)
- file:line — description of issue

## Warnings
- file — description of concern

## Notes
- Observation or suggestion
```

If no findings: short "LGTM" with one-line summary of what was reviewed.

## Skill Location

`~/.claude/skills/fireshark-pr-review/SKILL.md` (personal skill, not project-local, since it's workflow tooling rather than project source).

## Out of Scope

- Running `cargo test` or `cargo clippy` (those are build/CI concerns, not review)
- Reviewing non-Rust files
- Generating fixes (the skill reports findings, the user decides what to fix)
