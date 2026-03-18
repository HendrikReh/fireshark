# tshark-Based Stream Reassembly — Design Spec

## Purpose

Leverage tshark's TCP reassembly engine to extract stream payloads, HTTP request/response data, and TLS certificate information. This unblocks HTTP and certificate parsing without building a native TCP state machine.

## Architecture

Add `follow_stream` capability to `fireshark-tshark` that calls `tshark -z follow,{mode},raw,{stream_id}` and parses the output. Expose through `fireshark-backend` capability model and both CLI/MCP surfaces.

## tshark Follow Modes

| Mode | tshark flag | Output | Use case |
|------|-----------|--------|----------|
| `tcp` | `follow,tcp,raw,N` | Reassembled TCP bytes (hex) with direction | Generic payload inspection |
| `http` | `follow,http,ascii,N` | HTTP request + response text | HTTP analysis |
| `tls` | `follow,tls,raw,N` | Decrypted TLS payload (if keys available) | TLS payload inspection |

For v0.8, focus on `tcp` and `http`. TLS follow requires keylog files — defer to later.

## New Types

### In fireshark-tshark

```rust
pub enum FollowMode {
    Tcp,
    Http,
}

pub struct StreamSegment {
    pub direction: Direction,  // ClientToServer or ServerToClient
    pub data: Vec<u8>,
}

pub enum Direction {
    ClientToServer,
    ServerToClient,
}

pub struct StreamPayload {
    pub stream_id: u32,
    pub mode: FollowMode,
    pub client: String,    // "192.168.1.2:51514"
    pub server: String,    // "198.51.100.20:443"
    pub segments: Vec<StreamSegment>,
}
```

### In fireshark-backend

Add capability:
```rust
pub supports_reassembly: bool,  // true for tshark, false for native
```

Add method to `BackendCapture`:
```rust
pub fn follow_stream(&self, stream_id: u32, mode: FollowMode) -> Result<StreamPayload, BackendError>
```

For native backend: returns `Err(BackendError::Unsupported("reassembly requires tshark backend"))`.

For tshark backend: calls `fireshark_tshark::follow_stream`.

Note: This requires the tshark backend to retain the capture file path so it can re-invoke tshark for follow queries. Add `path: PathBuf` to `BackendCapture`.

## tshark Output Parsing

`tshark -z follow,tcp,raw,N -q -r file.pcap` produces:

```
===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 0
Node 0: 192.168.1.2:51514
Node 1: 198.51.100.20:443
===================================================================
	48656c6c6f         <-- Node 1 (server) data, hex, indented with tab
576f726c64           <-- Node 0 (client) data, hex, no indent
===================================================================
```

Lines starting with tab = server→client. Lines without tab = client→server. Hex data needs decoding.

For `follow,http,ascii,N`, output is similar but ASCII instead of hex, with HTTP headers visible.

## HTTP Extraction

From the reassembled HTTP stream, parse:
- Request line: method, URI, HTTP version
- Request headers (especially Host, Content-Type)
- Response status line: version, status code, reason
- Response headers

Store as:

```rust
pub struct HttpExchange {
    pub request_method: String,
    pub request_uri: String,
    pub request_host: Option<String>,
    pub response_status: u16,
    pub response_reason: String,
}
```

## TLS Certificate Extraction

Instead of reassembly, use tshark field extraction directly:

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields \
  -e frame.number -e x509sat.printableString -e x509ce.dNSName \
  -e x509sat.CountryName -e x509sat.OrganizationName
```

This extracts certificate subject/SAN fields without needing to reassemble TLS or parse ASN.1/DER. The certificate data is decoded by tshark.

Store as:

```rust
pub struct TlsCertInfo {
    pub packet_index: usize,
    pub common_name: Option<String>,
    pub san_dns_names: Vec<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
}
```

## CLI Integration

Extend `follow` command:

```bash
# Reassembled TCP payload (hex dump)
fireshark follow --backend tshark --payload capture.pcap 0

# HTTP exchange from stream
fireshark follow --backend tshark --http capture.pcap 0
```

New `--payload` flag shows the reassembled bytes (hex dump format).
New `--http` flag shows parsed HTTP request/response.

Both require `--backend tshark` (capability-gated).

## MCP Integration

New tool: `get_stream_payload(session_id, stream_id, mode)`:

```json
{
  "session_id": "abc",
  "stream_id": 0,
  "mode": "tcp"
}
```

Returns `StreamPayloadView` with segments and direction markers.

New tool: `get_certificates(session_id)`:

Returns certificate info for all TLS handshake packets.

## Testing

- `follow --backend tshark --payload` on fuzz fixture → reassembled bytes
- `follow --backend tshark --http` on an HTTP capture → method, URI, status
- `get_certificates` on a TLS capture → certificate subject/SAN
- Capability gate: `follow --payload` without tshark → clear error
- Parse tshark follow output with known hex → correct bytes

## New Files

- `crates/fireshark-tshark/src/follow.rs` — follow stream execution + output parsing
- `crates/fireshark-tshark/src/certs.rs` — certificate field extraction
- `crates/fireshark-backend/src/reassembly.rs` — StreamPayload, HttpExchange, TlsCertInfo types

## Modified Files

- `crates/fireshark-backend/src/capture.rs` — add path, follow_stream method, supports_reassembly
- `crates/fireshark-backend/src/backend.rs` — add supports_reassembly to capabilities
- `crates/fireshark-tshark/src/lib.rs` — export new modules
- `crates/fireshark-cli/src/follow.rs` — --payload and --http flags
- `crates/fireshark-cli/src/main.rs` — new flags on Follow command
- `crates/fireshark-mcp/src/server.rs` — get_stream_payload, get_certificates tools
- `crates/fireshark-mcp/src/tools.rs` — handlers
- `crates/fireshark-mcp/src/model.rs` — view types

## Out of Scope

- Native TCP reassembly (v1.0)
- TLS decryption with keylog files
- HTTP/2 stream multiplexing
- WebSocket frame parsing
- QUIC reassembly
