# CLI / MCP Feature Parity

Fireshark ships two binaries: `fireshark` (CLI) and `fireshark-mcp` (MCP server). This document tracks feature parity between them.

## Parity Matrix

| Capability | CLI | MCP | Status |
|---|---|---|---|
| Packet listing with display filter | `summary -f` | `list_packets` | Parity |
| Packet detail | `detail` (layer tree + color hex dump) | `get_packet` (structured JSON) | Parity (different format) |
| Capture statistics | `stats` | `summarize_capture` + `summarize_protocols` + `top_endpoints` | Parity |
| Decode issue listing | `issues` | `list_decode_issues` | Parity |
| Security audit | `audit --profile` | `audit_capture` with profile | Parity |
| Stream follow | `follow <id>` | `get_stream` | Parity |
| Stream reassembly | `follow --payload`, `follow --http` | `get_stream_payload` | Parity |
| Capture comparison | `diff` | `compare_captures` | Parity |
| Multi-criteria search | `search` | `search_packets` | Parity |
| TLS certificates | `certificates` | `get_certificates` | Parity |
| JSON export | `--json` on most commands | All tools return JSON | Parity |
| Display filter | `-f` flag | `filter` parameter | Parity |
| Color hex dump | `detail` command | N/A | CLI only |
| Finding escalation | N/A | `escalate_finding` | MCP only (session-based) |
| Finding explanation | N/A (shown in `audit` output) | `explain_finding` | MCP only |
| Capture description | Embedded in `stats` | `describe_capture` | Minor gap |
| Session management | N/A (stateless) | `open_capture`, `close_capture` | MCP only (by design) |

## Design Rationale

**CLI-only: Color hex dump** — The `detail` command renders a color-coded hex dump where each byte is colored by its protocol layer (Ethernet, IPv4, TCP, etc.). This is a visual feature that doesn't translate to JSON. The MCP `get_packet` tool returns structured layer data instead.

**MCP-only: Finding escalation** — `escalate_finding` marks a finding as escalated with analyst notes. This is inherently session-based: the escalation persists for the lifetime of the MCP session so subsequent queries reflect it. The CLI is stateless — each invocation is independent — so escalation has no place.

**MCP-only: Session management** — The MCP server maintains sessions because LLM-driven analysis is iterative (open → query → drill → audit → close). The CLI processes captures in a single invocation.

## Command Reference

### CLI (9 commands)

| Command | Purpose |
|---------|---------|
| `summary` | List packets with color-coded protocol summary |
| `detail` | Inspect a single packet (layer tree + hex dump) |
| `stats` | Capture statistics (packets, streams, protocols, endpoints) |
| `issues` | List decode issues |
| `audit` | Run security audit heuristics |
| `follow` | Follow a TCP/UDP stream (with optional reassembly) |
| `diff` | Compare two capture files |
| `search` | Multi-criteria packet search |
| `certificates` | Extract TLS certificates (requires tshark) |

### MCP (21 tools)

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Streams | `list_streams`, `get_stream`, `get_stream_payload` |
| Overview | `summarize_capture` |
| Comparison | `compare_captures` |
| Audit | `audit_capture`, `list_findings`, `explain_finding`, `escalate_finding` |
| TLS | `get_certificates` |

---

**Version:** 0.10.0 | **Last updated:** 2026-03-19 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
