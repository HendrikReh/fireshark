# Fireshark MCP Design

**Date:** 2026-03-16

**Goal:** Expose Fireshark's current offline packet-analysis capabilities to LLM hosts over MCP so an assistant can perform packet analysis and security-audit workflows against `.pcap` and `.pcapng` files.

## Decisions

- Scope v1 to offline capture analysis only. Live capture stays out of scope.
- Make the MCP server stateful. A client opens a capture once and reuses a `session_id` for follow-up queries.
- Expose both low-level packet/query tools and high-level audit tools in v1.
- Build the server directly on the Rust libraries, not by shelling out to `fireshark-cli`.
- Use the official Rust MCP SDK (`rmcp`) over stdio for local host integration.
- Start with MCP tools only in v1. Resources and prompts are optional later additions, not day-one requirements.
- Keep security findings heuristic and evidence-backed rather than pretending to provide IDS-grade detection.

## Recommended Approach

Add a new crate, `crates/fireshark-mcp`, that implements a stdio MCP server on top of the existing library stack:

- `fireshark-file` for offline capture ingestion
- `fireshark-dissectors` for protocol decoding
- `fireshark-core` for typed packet, issue, and summary models

The MCP crate should own only transport, session lifecycle, JSON-friendly response models, and audit orchestration. Packet parsing and decoding stay where they already belong.

This was chosen over a CLI wrapper because the CLI only emits text summaries, which is too lossy for packet drilldown and audit workflows. It was chosen over a resource-heavy MCP design because the project is still small and tool calls are the shortest path to a useful server.

## Architecture

### New Crate

Create `crates/fireshark-mcp` as a mixed library/binary crate:

- library modules hold session logic, audit logic, and tool handlers
- the binary is a thin stdio entrypoint that starts the MCP server

### Core Components

- `SessionManager`
  Creates, stores, expires, and closes sessions
- `CaptureSession`
  Owns decoded packets plus derived indexes and summaries
- `ToolHandlers`
  Maps MCP tool calls to session-aware analysis functions
- `AuditEngine`
  Produces explicit, evidence-backed findings from decoded packets and issues
- `McpTransport`
  Wires `rmcp` server capabilities, schemas, and stdio transport

### Boundaries

- `fireshark-mcp` may depend on the existing crates
- existing crates must not depend on `fireshark-mcp`
- no MCP protocol types should leak into `fireshark-core`, `fireshark-file`, or `fireshark-dissectors`
- the CLI remains a separate thin frontend

## Session Model

Each capture session should be process-local and ephemeral.

### Lifecycle

1. `open_capture(path)` validates the path, opens the file, decodes the capture, and stores an analyzed session.
2. Follow-up tools use `session_id` to query decoded packets, issues, summaries, or findings.
3. `close_capture(session_id)` removes the session.
4. Idle sessions expire automatically after a configured timeout.

### Default Limits

- maximum open sessions: 8
- default idle timeout: 15 minutes
- reject captures above a configured size threshold in v1 rather than degrading silently

### Session Contents

- `Vec<DecodedFrame>` for the decoded packet stream
- cached `PacketSummary` values per packet
- protocol histogram
- endpoint histogram
- decode issue index keyed by packet index
- lazily built findings cache

## MCP Surface

### Session Tools

- `open_capture(path)`
- `describe_capture(session_id)`
- `close_capture(session_id)`

### Low-Level Analysis Tools

- `list_packets(session_id, offset, limit, protocol?, has_issues?)`
- `get_packet(session_id, packet_index)`
- `list_decode_issues(session_id, kind?)`
- `summarize_protocols(session_id)`
- `top_endpoints(session_id, limit)`
- `search_packets(session_id, protocol?, source?, destination?, port?)`

### Audit Tools

- `audit_capture(session_id, profile?)`
- `list_findings(session_id, severity?, category?)`
- `explain_finding(session_id, finding_id)`

### Why Tools First

The MCP specification supports tools, resources, and prompts, but tools are enough for the first useful slice. Tool calls give the host an explicit action boundary, and Fireshark's current data fits naturally into structured tool results. Resources can be added later for packet exports or cached findings without changing the core session model.

## Response Model

All responses should be JSON-friendly and stable.

### Packet Summary Shape

- packet index
- protocol name
- source endpoint string
- destination endpoint string
- captured length
- whether the packet has decode issues

### Packet Detail Shape

- packet index
- summary object
- layer list with tagged objects such as `Ethernet`, `IPv4`, `IPv6`, `TCP`, `UDP`, `ARP`, `ICMP`
- decode issues
- raw length metadata

### Finding Shape

- `id`
- `severity`
- `category`
- `title`
- `summary`
- `evidence`

Evidence must include packet indexes or aggregate counts so the LLM can drill down with low-level tools.

## Audit Logic

V1 audit logic should be heuristic, explicit, and conservative.

### Initial Finding Categories

- malformed or truncated decode activity
- high concentrations of ARP or ICMP
- suspicious port usage patterns
- scan-like fan-out from a source endpoint
- heavy presence of unknown or undecoded traffic
- unusually skewed protocol mix
- likely cleartext services identified from ports only

### Non-Goals

- deep IDS signatures
- stream reassembly
- payload inspection frameworks
- TLS validation
- live traffic behavior analysis

## Error Handling

- invalid file path -> tool error from `open_capture`
- unsupported capture format -> propagated cleanly from `fireshark-file`
- unsupported link type -> propagated cleanly from `fireshark-file`
- unknown or expired session -> clear MCP tool error
- out-of-range packet index -> clear MCP tool error
- oversized capture -> explicit rejection in `open_capture`

## Security Constraints

- only permit access to capture files the MCP host explicitly asks to open
- avoid ambient filesystem browsing in v1
- never read arbitrary payload files outside the capture-open flow
- keep sessions isolated by `session_id`
- keep host-visible errors clear without leaking internal debug state by default

## Testing Strategy

- unit tests for session manager lifecycle and expiration
- unit tests for audit heuristics with synthetic decoded packets
- fixture-backed tests using `fixtures/smoke/minimal.pcap` and `fixtures/smoke/minimal.pcapng`
- integration tests for tool handlers without transport
- stdio end-to-end tests that launch the MCP server and execute a basic request flow

## Out Of Scope For V1

- live capture
- remote HTTP/SSE transport
- prompts
- resource subscriptions
- display-filter language
- stream following or reassembly
- binary payload export
- persistence of sessions across process restarts

## Future Extensions

- resource links for packet exports or serialized findings
- richer query predicates once typed filter primitives exist
- remote transport after the local stdio server is stable
- conversation or flow identity once Fireshark reaches later phases
