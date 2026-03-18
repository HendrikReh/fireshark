# Fireshark MCP Server Reference

Complete reference for the fireshark MCP server — installation, configuration, and all 21 tools.

## Installation

### Build

```bash
# From the fireshark repo root
cargo build -p fireshark-mcp --release
```

The binary is at `target/release/fireshark-mcp` (~4MB).

### Claude Code

```bash
# Automatic registration
claude mcp add fireshark ./target/release/fireshark-mcp
```

Or add manually to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "fireshark": {
      "command": "/path/to/fireshark/target/release/fireshark-mcp"
    }
  }
}
```

Restart Claude Code after adding.

### Codex

Add to your Codex MCP configuration:

```json
{
  "servers": {
    "fireshark": {
      "command": "/path/to/fireshark/target/release/fireshark-mcp",
      "transport": "stdio"
    }
  }
}
```

### Generic MCP Clients

Fireshark uses **stdio transport** — reads JSON-RPC from stdin, writes to stdout. Spawn the binary as a subprocess:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | ./target/release/fireshark-mcp
```

## Server Constraints

| Constraint | Value |
|-----------|-------|
| Transport | stdio only (no HTTP/WebSocket) |
| Captures | Offline pcap/pcapng only |
| Packet limit | 100,000 per session (configurable, max 1,000,000) |
| Sessions | 8 concurrent maximum |
| Idle timeout | 15 minutes per session |
| Page size | 1,000 results maximum per paginated response |

## Tools Reference (21 tools)

### Session Management

#### `open_capture`

Open a capture file and create an analysis session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to pcap/pcapng file |
| `backend` | string | no | `"native"` (default) or `"tshark"` |
| `max_packets` | integer | no | Max packets to load (default 100,000, cap 1,000,000) |

Returns: `session_id`, `backend`, `packet_count`, `decode_issue_count`, `protocol_counts`

#### `describe_capture`

Get metadata for an existing session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID from `open_capture` |

Returns: `session_id`, `packet_count`, `decode_issue_count`, `protocol_counts`, `top_endpoints`

#### `close_capture`

Close a session and free resources.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

Returns: `session_id`, `closed`

### Packet Queries

#### `list_packets`

List packet summaries with optional filtering.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `offset` | integer | no | Pagination offset (default 0) |
| `limit` | integer | no | Page size (default 100, max 1,000) |
| `protocol` | string | no | Filter by protocol name |
| `has_issues` | boolean | no | Filter to packets with/without decode issues |
| `filter` | string | no | Display filter expression (e.g., `"tcp and port 443"`) |

Returns: list of `PacketSummaryView` (index, timestamp, protocol, source, destination, length)

#### `get_packet`

Get full decoded detail for one packet.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `packet_index` | integer | yes | 0-indexed packet number |

Returns: `PacketDetailView` with all decoded layers, fields, and decode issues

#### `search_packets`

Multi-field packet search with optional display filter.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `offset` | integer | no | Pagination offset |
| `limit` | integer | no | Page size |
| `protocol` | string | no | Protocol name filter |
| `source` | string | no | Source address filter |
| `destination` | string | no | Destination address filter |
| `port` | integer | no | Port number (matches src or dst) |
| `text` | string | no | Free-text search across fields |
| `has_issues` | boolean | no | Filter by decode issue presence |
| `filter` | string | no | Display filter expression |

Returns: list of `PacketSummaryView`

#### `list_decode_issues`

List decode issues across the capture.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `kind` | string | no | Filter by kind: `"truncated"`, `"malformed"`, `"checksum_mismatch"` |
| `offset` | integer | no | Pagination offset |
| `limit` | integer | no | Page size |

Returns: list of `DecodeIssueEntryView` (packet_index, kind, offset)

#### `summarize_protocols`

Protocol distribution across the capture.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

Returns: list of `ProtocolCountView` (protocol, packet_count), sorted by count descending

#### `top_endpoints`

Busiest endpoints by packet count.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `limit` | integer | no | Number of endpoints (default 10) |

Returns: list of `EndpointCountView` (endpoint, packet_count), sorted by count descending

### Streams

#### `list_streams`

List TCP/UDP conversation streams.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `offset` | integer | no | Pagination offset |
| `limit` | integer | no | Page size |

Returns: list of `StreamView` (id, protocol, endpoint_a, endpoint_b, packet_count, byte_count, duration_ms)

#### `get_stream`

Get all packets in a specific stream.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `stream_id` | integer | yes | Stream ID |

Returns: `StreamView` + list of `PacketSummaryView`

### Capture Overview

#### `summarize_capture`

Comprehensive single-call capture summary.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

Returns: packet_count, stream_count, first/last timestamps, duration, protocol distribution, top endpoints, finding count

### Security Audit

#### `audit_capture`

Run heuristic security audit.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `profile` | string | no | `"security"`, `"dns"`, or `"quality"` (default: all) |

Returns: list of `FindingView`

**Audit heuristics (8):**

| Heuristic | Category | Profile | Severity |
|-----------|----------|---------|----------|
| Decode issue concentration | `decode_issues` | quality | high |
| Unknown traffic dominance | `unknown_traffic` | quality | medium |
| Endpoint fan-out (scan detection) | `scan_activity` | security | high |
| Suspicious destination ports | `suspicious_ports` | security | medium |
| Cleartext credential exposure | `cleartext_credentials` | security | high |
| Connection anomalies (SYN without SYN-ACK, RST storm, half-open) | `connection_anomaly` | security | medium/low |
| DNS tunneling indicators | `dns_tunneling` | dns | high |
| NXDOMAIN storm (DGA/malware) | `dns_anomaly` | dns | high |

#### `list_findings`

List audit findings with optional filtering.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `severity` | string | no | Filter: `"high"`, `"medium"`, `"low"` |
| `category` | string | no | Filter by category name |

Returns: list of `FindingView` (including escalation status)

#### `explain_finding`

Get full details for a specific finding.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `finding_id` | string | yes | Finding ID (e.g., `"scan-activity-10.0.0.1"`) |

Returns: `FindingView` with evidence packets

#### `escalate_finding`

Mark a finding as escalated with analyst notes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `finding_id` | string | yes | Finding ID |
| `notes` | string | yes | Analyst notes |

Returns: updated `FindingView` with `escalated: true`

### Capture Comparison

#### `compare_captures`

Compare two sessions and identify differences.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id_a` | string | yes | Baseline session |
| `session_id_b` | string | yes | Comparison session |

Returns: packet/stream deltas, new/missing hosts, new protocols, new ports

### tshark-Backed Tools

These tools require tshark to be installed.

#### `get_stream_payload`

Get reassembled TCP stream payload.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `stream_id` | integer | yes | Stream ID |
| `mode` | string | no | `"tcp"` (default) or `"http"` |

Returns: `StreamPayloadView` with directional segments (hex-encoded for TCP, ASCII for HTTP)

#### `get_certificates`

Extract TLS certificate information.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

Returns: list of `CertificateView` (packet_index, common_name, san_dns_names, organization)

## Example Workflow

A typical LLM analysis session:

```
1. open_capture({ path: "/tmp/traffic.pcap" })
   → session_id: "abc123", 691 packets, protocols: UDP 580, TCP 45, DNS 42...

2. summarize_capture({ session_id: "abc123" })
   → 244 streams, duration 26m, top endpoint 192.168.1.2 (412 packets)

3. audit_capture({ session_id: "abc123", profile: "security" })
   → 3 findings: scan activity, suspicious port 445, incomplete handshake

4. get_packet({ session_id: "abc123", packet_index: 42 })
   → Ethernet + IPv4 + TCP [SYN] to port 445, TTL 64

5. list_packets({ session_id: "abc123", filter: "tls and tls.handshake.type == 1" })
   → 5 TLS ClientHellos with SNI domains

6. escalate_finding({ session_id: "abc123", finding_id: "scan-activity-10.0.0.1", notes: "Confirmed port scan" })
   → finding escalated with notes

7. get_stream({ session_id: "abc123", stream_id: 5 })
   → 12 packets in TCP conversation

8. compare_captures({ session_id_a: "abc123", session_id_b: "def456" })
   → 3 new hosts, 1 new protocol (TLS)

9. close_capture({ session_id: "abc123" })
   → session closed
```

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
