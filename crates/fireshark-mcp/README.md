# fireshark-mcp

Offline MCP server for LLM-driven packet capture analysis and security audits.

## Overview

Exposes fireshark's capture analysis capabilities through the Model Context Protocol (MCP) over stdio transport. An LLM client opens a capture file, receives a session ID, and uses it for follow-up queries about packets, protocols, endpoints, security findings, and capture comparisons.

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

### Streams

| Tool | Description |
|------|-------------|
| `list_streams` | Paginated TCP/UDP conversation stream metadata |
| `get_stream` | All packets in a single conversation with stream metadata |
| `get_stream_payload` | Reassembled TCP payload for a stream (requires tshark backend) |

### Capture Overview

| Tool | Description |
|------|-------------|
| `summarize_capture` | Single-call capture summary: packets, streams, protocols, endpoints, timestamps, audit findings |

### Comparison

| Tool | Description |
|------|-------------|
| `compare_captures` | Compare two open sessions to identify new/missing hosts, protocols, and ports |

### Security Audit

| Tool | Description |
|------|-------------|
| `audit_capture` | Run heuristic security analysis (scan detection, suspicious ports, cleartext credential exposure, DNS tunneling detection). Accepts optional `profile` parameter: `"security"`, `"dns"`, or `"quality"`. Default (no profile) runs all heuristics |
| `list_findings` | List audit findings with severity and evidence |
| `explain_finding` | Get detailed explanation of a specific finding |

### TLS

| Tool | Description |
|------|-------------|
| `get_certificates` | Extract TLS certificate details: subject CN, SAN DNS names, organization (requires tshark backend) |

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
| `audit.rs` | Security heuristic engine (8 heuristics: decode issues, unknown traffic, scan activity, suspicious ports, cleartext credentials, DNS tunneling, NXDOMAIN storm, connection anomalies) |
| `model.rs` | Serializable view types for MCP responses |
| `filter.rs` | Shared filter utilities |

---

**Version:** 0.8.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
