# fireshark-mcp

Offline MCP server for LLM-driven packet capture analysis and security audits.

## Overview

Exposes fireshark's capture analysis capabilities through the Model Context Protocol (MCP) over stdio transport. An LLM client opens a capture file, receives a session ID, and uses it for follow-up queries about packets, protocols, endpoints, and security findings.

## Usage

```bash
cargo run -p fireshark-mcp
```

The server speaks MCP over stdin/stdout. Connect with any MCP-compatible client.

## Tools

### Session Management

| Tool | Description |
|------|-------------|
| `open_capture` | Open a pcap/pcapng file, decode all packets, return session metadata |
| `describe_capture` | Get capture summary: packet count, protocol breakdown, top endpoints |
| `close_capture` | Close a session and free resources |

### Packet Queries

| Tool | Description |
|------|-------------|
| `list_packets` | Paginated packet summaries with optional protocol/issue filters |
| `get_packet` | Full packet detail with all layer fields and decode issues |
| `search_packets` | Search packets by protocol, address, port, text, or issues |
| `list_decode_issues` | Paginated decode issues with optional kind filter |
| `summarize_protocols` | Protocol distribution across the capture |
| `top_endpoints` | Most active endpoints by packet count |

### Security Audit

| Tool | Description |
|------|-------------|
| `audit_capture` | Run heuristic security analysis (scan detection, suspicious ports, etc.) |
| `list_findings` | List audit findings with severity and evidence |
| `explain_finding` | Get detailed explanation of a specific finding |

## Constraints

- Stdio transport only (no HTTP/WebSocket)
- Offline captures only (no live capture)
- 100,000 packet limit per capture
- 8 concurrent sessions maximum
- 15-minute idle session timeout
- Paginated query tools clamp `limit` to 1,000 results per call

## Architecture

| Module | Purpose |
|--------|---------|
| `server.rs` | MCP server with tool routing |
| `tools.rs` | Tool handler implementations |
| `session.rs` | Session lifecycle management |
| `analysis.rs` | Capture loading and analysis |
| `query.rs` | Packet query and filtering logic |
| `audit.rs` | Security heuristic engine |
| `model.rs` | Serializable view types for MCP responses |
| `filter.rs` | Shared filter utilities |

---

**Version:** 0.3.0 | **Last updated:** 2026-03-16 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
