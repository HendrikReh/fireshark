# Fireshark MCP Smoke Test

Date: 2026-03-16

## Startup

Command:

```bash
cargo run -p fireshark-mcp
```

Transport:

- MCP over stdio

Fixture:

- `fixtures/smoke/minimal.pcap`

## Transcript

### 1. Open the capture

Request:

```json
{
  "name": "open_capture",
  "arguments": {
    "path": "fixtures/smoke/minimal.pcap"
  }
}
```

Response:

```json
{
  "session_id": "session-1",
  "packet_count": 1,
  "decode_issue_count": 0,
  "protocol_counts": [
    {
      "protocol": "TCP",
      "packet_count": 1
    }
  ]
}
```

### 2. List packets

Request:

```json
{
  "name": "list_packets",
  "arguments": {
    "session_id": "session-1",
    "offset": 0,
    "limit": 10
  }
}
```

Response:

```json
{
  "packets": [
    {
      "index": 0,
      "protocol": "TCP",
      "source": "192.0.2.10:51514",
      "destination": "198.51.100.20:443",
      "length": 54,
      "has_issues": false
    }
  ]
}
```

### 3. Run the audit engine

Request:

```json
{
  "name": "audit_capture",
  "arguments": {
    "session_id": "session-1"
  }
}
```

Response:

```json
{
  "findings": []
}
```

## Notes

- The `session_id` is process-local and will vary by run.
- The smoke fixture currently produces one decoded TCP packet and no audit findings.
- End-to-end coverage for `open_capture`, `list_packets`, and `audit_capture` over stdio is verified by `crates/fireshark-mcp/tests/stdio_smoke.rs`.
