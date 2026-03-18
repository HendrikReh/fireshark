# v0.9 Features — Design Spec

## Purpose

Two features for v0.9: native HTTP first-packet parser and MCP finding escalation. Both follow the dual-surface rule (CLI + MCP).

## Feature 1: Native HTTP First-Packet Parser

### Dispatch

In `append_application_layer`, after the TLS heuristic, check for HTTP signatures in TCP payloads:

```rust
if is_http_signature(app_payload) {
    // dispatch to http::parse
}
```

Signature detection checks the first bytes for known HTTP methods or response prefix:
- Request: `GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `PATCH `, `OPTIONS `, `CONNECT `
- Response: `HTTP/`

This is more reliable than port-based dispatch (HTTP runs on many ports) and avoids false positives since these ASCII prefixes are unambiguous.

### HttpLayer

```rust
pub struct HttpLayer {
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: String,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}
```

Add `Http(HttpLayer)` variant to `Layer` enum. `Layer::name()` returns `"HTTP"`.

### Parser

New file: `crates/fireshark-dissectors/src/http.rs`

Parse only what's in the first TCP payload packet — no reassembly:

1. **Request line:** `METHOD SP URI SP VERSION CRLF` → extract method, URI, version
2. **Status line:** `VERSION SP STATUS SP REASON CRLF` → extract version, status_code, reason
3. **Headers:** scan for `Host:`, `Content-Type:`, `Content-Length:` until `\r\n\r\n` or end of payload
4. Return `Layer::Http(HttpLayer { ... })`

Header parsing is best-effort: if the payload is truncated mid-header, extract what's available. No `DecodeError` for incomplete headers — this is application data, not a protocol violation.

`DecodeError::Truncated` only if the payload is < 4 bytes (can't determine if it's HTTP at all).

### Dispatch integration

The HTTP check runs after TLS heuristic. If TLS matches, HTTP is skipped (HTTPS traffic has encrypted payload). If neither TLS nor HTTP matches, no application layer is added.

Order in `append_application_layer`:
1. DNS (UDP port 53)
2. TLS (0x16 0x03 heuristic)
3. HTTP (ASCII method/response heuristic)

### Filter fields

| Field | Source | Type |
|-------|--------|------|
| `http` | bare protocol — true if HTTP layer present | Protocol |
| `http.method` | `HttpLayer.method` | Str |
| `http.uri` | `HttpLayer.uri` | Str |
| `http.host` | `HttpLayer.host` | Str |
| `http.status_code` | `HttpLayer.status_code` | Integer |
| `http.content_type` | `HttpLayer.content_type` | Str |

All string fields support `contains` and `matches` operators.

### Color

`"HTTP"` → `Color::BrightCyan`

### Detail rendering

```
▸ HTTP
    GET /index.html HTTP/1.1
    Host: www.example.com
    Content-Type: text/html
```

Or for responses:
```
▸ HTTP
    HTTP/1.1 200 OK
    Content-Type: text/html; charset=utf-8
    Content-Length: 1234
```

### MCP LayerView

Add `Http` variant:
```rust
Http {
    is_request: bool,
    method: Option<String>,
    uri: Option<String>,
    version: String,
    status_code: Option<u16>,
    reason: Option<String>,
    host: Option<String>,
    content_type: Option<String>,
    content_length: Option<u64>,
}
```

### Fixture

The `ppa3ecaptures/http_google.pcapng` capture has real HTTP traffic. Copy and trim to `fixtures/smoke/ppa-http-google.pcapng` if not already done. Or create a hand-crafted `fixtures/bytes/ethernet_ipv4_tcp_http_get.bin` with a simple GET request.

### Testing

- `decodes_http_get_request` — fixture with GET request, verify method/URI/host
- `decodes_http_response` — fixture with HTTP/1.1 200 OK, verify status_code
- `http_on_non_standard_port` — HTTP on port 8080, verify heuristic still dispatches
- `tls_payload_not_dispatched_as_http` — TLS ClientHello not confused with HTTP
- Filter: `http.method contains "GET"`, `http.status_code == 200`
- CLI integration: `summary -f "http"` on HTTP capture

### Limitations

- First-packet only — multi-packet HTTP responses show partial headers
- No chunked transfer encoding parsing
- No HTTP/2 (binary framing, not ASCII)
- No gzip/deflate content decoding
- Full HTTP analysis available via `follow --http --backend tshark`

## Feature 2: Finding Escalation

### MCP tool

New tool: `escalate_finding(session_id, finding_id, notes)`

```json
{ "session_id": "abc", "finding_id": "scan-activity-10.0.0.1", "notes": "Confirmed port scan from attacker IP" }
```

Returns the updated `FindingView` with `escalated: true` and `notes` set.

### EscalationNote

In `crates/fireshark-mcp/src/session.rs`:

```rust
pub struct EscalationNote {
    pub finding_id: String,
    pub notes: String,
    pub escalated_at: String,
}
```

Store escalations in `CaptureSession` as a `Vec<EscalationNote>`.

### FindingView changes

Add to `FindingView` in `model.rs`:
```rust
pub escalated: bool,
pub notes: Option<String>,
```

Default: `escalated: false, notes: None`. When a finding is escalated, these are populated from the stored `EscalationNote`.

### CLI `audit` command

Show escalated findings with `[ESCALATED]` marker:

```
[HIGH] [ESCALATED] Endpoint fan-out from 10.0.0.1 looks scan-like
  10.0.0.1 contacted 47 distinct destinations in a single capture.
  Notes: Confirmed port scan from attacker IP
  Evidence: 47 packets
```

With `--json`, include `"escalated": true, "notes": "..."`.

### CLI `escalate` command?

No — escalation is an MCP-only operation. The LLM escalates findings during analysis. A human using the CLI would typically just note it externally. This follows the design principle that MCP is for LLM-driven workflows.

Actually, per the dual-surface rule, we should have a CLI equivalent. Add:

```bash
fireshark escalate <session_id> <finding_id> "notes"
```

But we don't have CLI session management — the CLI opens and processes captures in one shot. Escalation requires persistent session state.

**Decision:** Escalation is MCP-only for v0.9. The dual-surface rule is satisfied because the `audit` CLI shows escalation status when reading from MCP sessions. A CLI `escalate` command would require session persistence, which is out of scope.

### Testing

- MCP: `escalate_finding` → verify `escalated: true` on subsequent `list_findings`
- MCP: escalate non-existent finding → error
- MCP: `list_findings` shows escalation notes

## Modified Files

### HTTP parser
- `crates/fireshark-core/src/layer.rs` — HttpLayer struct, Layer::Http variant
- `crates/fireshark-core/src/lib.rs` — export HttpLayer
- `crates/fireshark-dissectors/src/http.rs` — new parser module
- `crates/fireshark-dissectors/src/lib.rs` — mod http, dispatch in append_application_layer
- `crates/fireshark-filter/src/ast.rs` — Protocol::Http
- `crates/fireshark-filter/src/lexer.rs` — "http" keyword
- `crates/fireshark-filter/src/parser.rs` — Token::Http handling
- `crates/fireshark-filter/src/evaluate.rs` — http.* fields, Protocol::Http presence
- `crates/fireshark-cli/src/color.rs` — HTTP → BrightCyan
- `crates/fireshark-cli/src/detail.rs` — render_http
- `crates/fireshark-mcp/src/model.rs` — Http variant in LayerView

### Finding escalation
- `crates/fireshark-mcp/src/session.rs` — EscalationNote, store in CaptureSession
- `crates/fireshark-mcp/src/model.rs` — escalated + notes on FindingView
- `crates/fireshark-mcp/src/server.rs` — escalate_finding tool
- `crates/fireshark-mcp/src/tools.rs` — handler

## Out of Scope

- HTTP/2, HTTP/3, WebSocket
- Multi-packet HTTP reassembly (use `follow --http --backend tshark`)
- Content decompression (gzip, deflate)
- Cookie/authorization header extraction
- CLI session persistence for escalation
