# Fireshark Architecture

## Table of Contents

- [1. System Overview](#1-system-overview)
- [2. Architecture Diagram](#2-architecture-diagram)
- [3. Data Flow](#3-data-flow)
- [4. Crate Boundaries](#4-crate-boundaries)
- [5. Key Design Decisions](#5-key-design-decisions)
- [6. Extension Points](#6-extension-points)
- [7. Cross-Cutting Concerns](#7-cross-cutting-concerns)
- [8. Constraints and Limitations](#8-constraints-and-limitations)
- [9. Phase Roadmap](#9-phase-roadmap)

## 1. System Overview

Fireshark is a Wireshark-inspired packet analyzer written in Rust. It is **library-first**: the CLI and MCP server are thin consumers of a shared library stack. There is no monolithic binary; all parsing, dissection, filtering, and analysis logic lives in reusable library crates.

Development follows a phased approach:

| Phase | Focus | Status |
|-------|-------|--------|
| **Crawl** | Offline pcap/pcapng parsing, protocol dissection, CLI, display filters, MCP server, stream tracking | Complete |
| **Walk** | Live capture backends, tshark backend, TCP reassembly, capture comparison, JSON export, checksum validation, tshark stream reassembly, TLS certificate extraction | Active |
| **Run** | String filters (contains/matches), audit profiles, HTTP dissector, finding escalation, advanced statistics | Active |

The crawl phase is complete. Walk phase is active — stream tracking, display filters, tshark backend, JSON export, checksum validation, capture comparison, tshark stream reassembly, and TLS certificate extraction are delivered. Live capture is the remaining walk milestone. Each phase delivers vertical slices of functionality, not speculative frameworks.

## 2. Architecture Diagram

### Crate Dependency Graph

```
                       +-----------------+
                       | fireshark-core  |  (zero external dependencies)
                       +-----------------+
                        /    |    |     \
                       /     |    |      \
                      v      v    v       v
           +--------+  +----------+  +----------+  +----------+
           | -file  |  | -dissect |  | -filter  |  | -tshark  |
           +--------+  +----------+  +----------+  +----------+
               \             |                          /
                \            |                         /
                 v           v                        v
               +----------------------------------+
               |        fireshark-backend         |  (analysis, audit, compare, native/tshark adapters)
               +----------------------------------+
                      /                     \
                     v                       v
               +----------+           +----------+
               | -cli     |           | -mcp     |
               +----------+           +----------+
```

Key change from earlier: `fireshark-backend` now hosts `AnalyzedCapture` (capture loading + aggregation) and `AuditEngine` (8 security heuristics), making them available to both CLI and MCP without the CLI depending on the MCP server crate.

### Exact Dependency Edges

```
fireshark-core       -> (none)
fireshark-file       -> fireshark-core, pcap-file, thiserror
fireshark-dissectors -> fireshark-core, thiserror
fireshark-filter     -> fireshark-core, thiserror, regex
fireshark-backend    -> fireshark-core, fireshark-file, fireshark-dissectors, fireshark-tshark, thiserror
fireshark-cli        -> fireshark-core, fireshark-file, fireshark-dissectors, fireshark-filter, fireshark-backend, fireshark-tshark, clap, colored, serde, serde_json
fireshark-mcp        -> fireshark-core, fireshark-filter, fireshark-backend, fireshark-tshark, rmcp, schemars, serde, serde_json, thiserror, tokio
fireshark-tshark     -> thiserror
```

Key observation: `fireshark-cli` does **not** depend on `fireshark-mcp`. The audit engine and capture analysis logic live in `fireshark-backend`, shared by both CLI and MCP.

Key observation: `fireshark-core` has **zero external dependencies**. It defines only domain types using `std`. The three middle crates (`-file`, `-dissectors`, `-filter`) depend only on `fireshark-core` (plus minimal external deps) and do not depend on each other. `fireshark-filter` added a `regex` dependency in v0.7 for the `matches` string operator. The two leaf crates (`-cli`, `-mcp`) compose the middle crates into user-facing applications.

## 3. Data Flow

### CLI Path

```
capture.pcap
    |
    v
CaptureReader::open()          [fireshark-file]
    |  yields Iterator<Item = Result<Frame, CaptureError>>
    v
Pipeline::new(reader, decode_packet)   [fireshark-core + fireshark-dissectors]
    |  yields Iterator<Item = Result<DecodedFrame, PipelineError>>
    v
+-- summary command --------------------------------------------------------+
|   DecodedFrame.summary() -> PacketSummary                                 |
|   Optional: parse(filter_str) -> Expr, evaluate(&expr, &decoded) -> bool  |
|   Print color-coded one-line-per-packet table                             |
+-- detail command ---------------------------------------------------------+
|   DecodedFrame.packet().layers() -> layer tree rendering                  |
|   DecodedFrame.packet().spans() + frame.data() -> color-coded hex dump    |
+---------------------------------------------------------------------------+
```

### MCP Path

```
MCP client (LLM)
    |  stdio JSON-RPC
    v
FiresharkMcpServer              [fireshark-mcp/server.rs]
    |  routes to ToolService
    v
ToolService                     [fireshark-mcp/tools.rs]
    |  acquires Mutex<SessionManager>
    v
SessionManager                  [fireshark-mcp/session.rs]
    |  manages CaptureSession lifecycle (open, touch, expire, close)
    v
AnalyzedCapture::open()         [fireshark-mcp/analysis.rs]
    |  CaptureReader -> Pipeline -> Vec<DecodedFrame>
    |  pre-computes protocol_counts, endpoint_counts
    v
query module / AuditEngine      [fireshark-mcp/query.rs, audit.rs]
    |  packet listing, search, protocol summary, security findings
    v
model module                    [fireshark-mcp/model.rs]
    |  serializable view types (serde) for MCP JSON responses
    v
MCP client
```

### Type Progression Through the Pipeline

| Stage | Type | Defined In |
|-------|------|------------|
| Raw file bytes | `Frame` | `fireshark-core::frame` |
| After dissection | `Packet` (layers + issues + spans) | `fireshark-core::packet` |
| Paired | `DecodedFrame` (Frame + Packet + optional stream ID) | `fireshark-core::pipeline` |
| Stream tracking | `StreamTracker` (assigns stream IDs via `TrackingPipeline`) | `fireshark-core::stream` |
| Summary | `PacketSummary` | `fireshark-core::summary` |
| Filter AST | `Expr` | `fireshark-filter::ast` |
| MCP response | `*View` structs | `fireshark-mcp::model` |

## 4. Crate Boundaries

### fireshark-core

**Responsibility:** Define all domain types shared across crates. Zero external dependencies.

**Key Exports:**

| Type | Purpose |
|------|---------|
| `Frame`, `FrameBuilder` | Raw captured frame with timestamp, captured/original length, raw bytes |
| `Packet` | Decoded protocol layers + decode issues + byte spans |
| `Layer` | Enum wrapping typed layer structs (`Ethernet`, `Arp`, `Ipv4`, `Ipv6`, `Tcp`, `Udp`, `Icmp`, `Dns`, `TlsClientHello`, `TlsServerHello`, `Http`) |
| `LayerSpan` | Byte offset + length for hex dump coloring |
| `Pipeline<I, D>`, `DecodedFrame` | Generic iterator pairing frame source with decoder function |
| `TrackingPipeline<I, D>` | Wraps `Pipeline`, assigns stream IDs via `StreamTracker` during iteration |
| `StreamKey` | Canonical 5-tuple (lower addr/port, higher addr/port, protocol) for bidirectional conversations |
| `StreamMetadata` | Per-stream statistics: ID, key, packet count, byte count, first/last seen |
| `StreamTracker` | Maps `StreamKey` to monotonic `u32` stream IDs, accumulates metadata |
| `PipelineError<F, D>` | Enum distinguishing frame-source errors from decode errors |
| `PacketSummary` | One-line display summary (protocol, endpoints, ports, timestamp, length) |
| `DecodeIssue`, `DecodeIssueKind` | Structured decode problem at a byte offset (Truncated, Malformed, or ChecksumMismatch) |
| `TcpFlags`, `IcmpDetail` | Sub-types for protocol layer fields |

**Source:** `crates/fireshark-core/src/lib.rs`

### fireshark-file

**Responsibility:** Read pcap and pcapng files, yield `Frame` objects. Validates link type at open time.

**Key Exports:**

| Type | Purpose |
|------|---------|
| `CaptureReader` | `Iterator<Item = Result<Frame, CaptureError>>` over a capture file |
| `CaptureError` | Io, Parse, UnsupportedFormat, UnsupportedLinkType |

**Depends on:** `fireshark-core`, `pcap-file`, `thiserror`

**Source:** `crates/fireshark-file/src/lib.rs`

### fireshark-dissectors

**Responsibility:** Decode raw Ethernet frame bytes into typed `Packet` with protocol layers.

**Key Exports:**

| Symbol | Purpose |
|--------|---------|
| `decode_packet(bytes: &[u8]) -> Result<Packet, DecodeError>` | Entry point for full-stack dissection |
| `DecodeError` | Truncated (with layer name + offset) or Malformed |

**Internal structure:** One module per protocol (`ethernet`, `arp`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `dns`, `tls`, `http`), each with a `parse()` function. Network-layer dissectors return the crate-internal `NetworkPayload` struct carrying the parsed layer, the IP protocol number, and a payload slice for transport-layer dispatch. Application-layer dispatch uses three strategies: DNS is dispatched by port number (UDP port 53), TLS uses heuristic dispatch on any TCP port by inspecting the TLS record header bytes (`0x16 0x03`), and HTTP uses ASCII signature heuristic dispatch on TCP payloads (GET, POST, HTTP/).

**Depends on:** `fireshark-core`, `thiserror`

**Source:** `crates/fireshark-dissectors/src/lib.rs`

### fireshark-filter

**Responsibility:** Parse and evaluate Wireshark-style display filter expressions against decoded frames.

**Key Exports:**

| Symbol | Purpose |
|--------|---------|
| `parse(input: &str) -> Result<Expr, FilterError>` | Hand-written lexer + recursive descent parser |
| `evaluate(expr: &Expr, decoded: &DecodedFrame) -> bool` | Field resolution and comparison logic |
| `FilterError` | Parse-time error type |
| `ast::Expr`, `ast::Protocol`, `ast::Value`, etc. | AST types (public for inspection) |
| `lexer` module | Public for token-level access |

**Pipeline:** `input string -> lexer -> tokens -> parser -> Expr AST -> evaluator(DecodedFrame) -> bool`

**Depends on:** `fireshark-core`, `thiserror`, `regex`

**Source:** `crates/fireshark-filter/src/lib.rs`

### fireshark-cli

**Responsibility:** Thin CLI binary (`fireshark`) with 9 subcommands: `summary`, `detail`, `stats`, `issues`, `audit`, `follow`, `diff`, `search`, `certificates`. Supports `--json` flag on `summary`, `stats`, `issues`, `audit`, `search`, `certificates` for JSONL output. All presentation logic (color, formatting, hex dump) is confined here.

**Modules:**

| Module | Purpose |
|--------|---------|
| `summary.rs` | Packet listing with optional display filter, protocol coloring |
| `detail.rs` | Single-packet layer tree + hex dump |
| `follow.rs` | Follow stream: all packets in a TCP/UDP conversation by stream ID |
| `stats.rs` | Capture statistics: packets, streams, duration, protocols, endpoints |
| `issues.rs` | Decode issue listing |
| `audit.rs` | Security audit heuristics |
| `diff.rs` | Capture comparison: new/missing hosts, protocols, ports |
| `search.rs` | Multi-criteria packet search (protocol, address, port, text, issues) |
| `certificates.rs` | TLS certificate extraction via tshark |
| `hexdump.rs` | Color-coded hex dump using `LayerSpan` data |
| `color.rs` | Protocol-to-ANSI-color mapping |

**Depends on:** `fireshark-core`, `fireshark-file`, `fireshark-dissectors`, `fireshark-filter`, `fireshark-backend`, `fireshark-tshark`, `clap`, `colored`, `serde`, `serde_json`

Note: the CLI does **not** depend on `fireshark-mcp`. The audit command uses `AuditEngine` from `fireshark-backend`.

**Source:** `crates/fireshark-cli/src/main.rs`

### fireshark-mcp

**Responsibility:** Offline MCP server for LLM-driven capture analysis and security audits. Stateful session model with idle timeout.

**Modules:**

| Module | Purpose |
|--------|---------|
| `server.rs` | `FiresharkMcpServer` implementing `ServerHandler` with `#[tool_router]` macro |
| `tools.rs` | `ToolService` bridging MCP tool calls to session/query/audit logic |
| `session.rs` | `SessionManager` with `CaptureSession`, idle expiration, max-session cap |
| `query.rs` | Packet listing, search, decode issue listing, protocol summary, top endpoints |
| `model.rs` | Serializable view types (`*View` structs with serde + JsonSchema) for MCP JSON-RPC responses |
| `filter.rs` | Shared filter utilities |

Note: `AnalyzedCapture` and `AuditEngine` live in `fireshark-backend`, not here. The MCP crate re-exports them for backward compatibility but does not own the analysis or audit logic.

Tool API reference: [docs/references/mcp-server.md](../references/mcp-server.md)

**MCP Tools (21 total):**

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Streams | `list_streams`, `get_stream`, `get_stream_payload` |
| Capture overview | `summarize_capture` |
| Comparison | `compare_captures` |
| Audit | `audit_capture`, `list_findings`, `explain_finding`, `escalate_finding` |
| TLS | `get_certificates` |

**Depends on:** `fireshark-core`, `fireshark-filter`, `fireshark-backend`, `fireshark-tshark`, `rmcp`, `schemars`, `serde`, `serde_json`, `thiserror`, `tokio`

**Source:** `crates/fireshark-mcp/src/lib.rs`

## 5. Key Design Decisions

### Separation of file parsing from protocol dissection

File parsing (`fireshark-file`) and protocol dissection (`fireshark-dissectors`) are in separate crates with no dependency between them. This means:

- `CaptureReader` produces generic `Frame` objects with raw bytes; it knows nothing about Ethernet, IP, or TCP.
- `decode_packet` takes a `&[u8]` slice; it knows nothing about pcap headers, file formats, or timestamps.
- The `Pipeline` type in `fireshark-core` composes them generically: `Pipeline<I, D>` where `I` is any frame iterator and `D` is any decode function.

This enables future frame sources (live capture, memory buffers, mock data) without touching dissection code, and enables dissector testing without real capture files.

### Typed layers over ad hoc byte inspection

Each protocol is a concrete Rust struct (`Ipv4Layer`, `TcpLayer`, etc.) wrapped in a `Layer` enum. All field extraction happens once, during dissection. Downstream code (summaries, filters, MCP queries, hex dump) operates on typed fields, never re-parsing raw bytes.

Benefits:
- Compile-time exhaustiveness checking on `Layer` match arms
- Field access is a struct field read, not a byte-offset calculation
- Adding a field to a layer struct is a compilation error until all consumers handle it

### Hand-written lexer and parser for filters

`fireshark-filter` uses a hand-written lexer (`lexer.rs`) and recursive descent parser (`parser.rs`) with no parser generator dependency. This was chosen because:

- The grammar is small (boolean operators, field comparisons, shorthands, CIDR literals)
- A hand-written parser gives precise error messages at specific token positions
- It avoids build-time code generation and keeps compile times fast
- The lexer must disambiguate IPv4 addresses, IPv6 addresses, CIDR notation, and integer literals -- context-sensitive tokenization that is awkward in generated parsers

### No chrono dependency for timestamps

Timestamps are stored as `std::time::Duration` (since Unix epoch) in `Frame`. The CLI formats them using the Hinnant `civil_from_days` algorithm in `crates/fireshark-cli/src/timestamp.rs` -- a 15-line function that correctly handles leap years and century rules. This avoids pulling in `chrono` (500+ types) for a single formatting operation.

### Parallel LayerSpan tracking instead of embedded offsets

Each `Packet` carries a parallel `Vec<LayerSpan>` alongside its `Vec<Layer>`. Spans record where each layer lives in the raw frame data (byte offset + length). This design was chosen over embedding offset fields in each layer struct because:

- Layer structs remain pure protocol data without presentation concerns
- Spans are only needed for hex dump coloring -- most consumers ignore them
- The `Packet::with_spans` constructor accepts an empty `Vec` when spans are not available, making them optional
- Keeping spans parallel avoids inflating every layer struct by 16 bytes

### Zero-dependency core crate

`fireshark-core` has zero external dependencies (`[dependencies]` is empty in its `Cargo.toml`). All types use only `std`. This is deliberate: the core types are the API contract between all crates, and minimizing their dependency surface maximizes reuse and minimizes compile-time coupling.

### TrackingPipeline as an iterator adapter

`TrackingPipeline<I, D>` wraps `Pipeline<I, D>` and intercepts each successfully decoded frame to extract the 5-tuple and assign a stream ID via `StreamTracker`. The stream ID is set on `DecodedFrame` via `with_stream_id()`. After iteration, call `into_tracker()` to retrieve the accumulated `StreamTracker` with all stream metadata.

This design was chosen over baking stream tracking into `Pipeline` directly because:

- Not all consumers need stream tracking (e.g., simple summary listing)
- The tracker state (`HashMap` + `Vec<StreamMetadata>`) adds overhead per packet
- Keeping it as a wrapper follows the Rust iterator adapter pattern (like `Peekable`, `Enumerate`)
- Consumers that need stream data use `TrackingPipeline`; consumers that do not use `Pipeline`

### Canonical 5-tuple normalization

`StreamKey` normalizes the direction of a conversation by placing the "lower" `(addr, port)` pair first (lexicographic comparison). This ensures both directions of a TCP or UDP conversation map to the same key without maintaining separate forward/reverse entries. The protocol number (`6` for TCP, `17` for UDP) is part of the key, so TCP and UDP conversations between the same endpoints are distinct streams.

### Native vs tshark Backend Design Rationale

Fireshark includes an optional tshark backend (`fireshark-tshark`, `fireshark-backend`) for broad protocol coverage, but the native Rust dissectors are the core of the product -- not redundant with tshark.

**Why fireshark maintains its own dissectors despite tshark availability:**

The native dissectors produce a typed layer model (`TcpLayer.flags.syn`, `DnsLayer.query_name`) where every protocol field is a concrete Rust struct field. tshark emits flat string key-value pairs that cannot be pattern-matched, type-checked, or fed into Rust data structures without ad hoc string parsing. The typed model is the foundation that makes the rest of the product possible.

**Capabilities that are native-only:**

| Capability | Why it requires native dissectors |
|-----------|-----------------------------------|
| Security audit engine (8 heuristics) | Heuristics inspect typed fields (e.g., TCP flag combinations for scan detection, DNS payload lengths for tunneling detection, NXDOMAIN response counting for DGA detection). Flat string fields from tshark cannot feed this logic. |
| Stream tracking with `tcp.stream` filter and `follow` command | The `StreamTracker` assigns stream IDs during pipeline iteration by extracting 5-tuples from typed layers. tshark's conversation tracking is opaque and cannot participate in fireshark's filter or pipeline model. |
| Display filter evaluation (`tcp.flags.syn and ip.ttl > 64`) | The filter evaluator resolves field names against typed `Layer` variants. tshark has its own separate filter engine whose results cannot feed back into fireshark's pipeline. |
| Color-coded hex dump with per-layer byte spans | `LayerSpan` records are produced during native dissection. tshark does not expose byte offsets for individual protocol layers. |

**What tshark provides:**

| Capability | Detail |
|-----------|--------|
| Broad protocol identification | 3,000+ protocols vs fireshark's 10 |
| Quick triage of unsupported protocols | Useful when a capture contains protocols fireshark does not yet dissect |
| Correctness oracle for differential testing | tshark output serves as a reference to validate native dissector correctness |
| Stream reassembly | TCP stream payload reassembly and HTTP request/response extraction via `follow --payload` and `follow --http` |
| TLS certificate extraction | Subject CN, SAN DNS names, organization from TLS handshakes via `get_certificates` MCP tool |

**Design principle:** Fireshark owns the product API surface (the `Layer` enum, `Pipeline`, `StreamTracker`, filter evaluator, audit engine). tshark is an optional backend behind the `BackendCapture` abstraction. CLI and MCP commands work identically with either backend, but features that require typed layer access (audit, streams, filters, detail hex dump) are only available with the native backend.

### Native/tshark Ownership Model

Native dissectors own the packet facts fireshark reasons over. tshark owns breadth, reassembly, and deep long-tail protocol coverage. The boundary is: native runs per-packet in tight loops during pipeline iteration; tshark runs per-stream or per-capture on demand.

**Protocol ownership matrix:**

| Protocol | Native scope | tshark scope | Rationale |
|----------|-------------|-------------|-----------|
| Ethernet | Full (destination, source, EtherType, spans) | No gain | Tiny, stable, anchors framing and dispatch |
| ARP | Full (operation, addresses) | No gain | Small parser, feeds endpoint identity |
| IPv4 | Base header (addresses, TTL, flags, checksum) | Options, reassembly | Core fields drive filters/streams/audit; rare options delegate |
| IPv6 | Base 40-byte header (addresses, hop limit, flow label) | Extension headers, fragmentation | Fixed header is simple; extension chains are complex and rare |
| TCP | Base header (ports, flags, seq/ack, window, data_offset) | Options, reassembly, conversation details | Base fields are critical for streams/audit; reassembly is hard |
| UDP | Full (ports, length) | No need | Tiny, feeds DNS/app dispatch |
| ICMP | Common types (echo, destination unreachable) | Exotic type-specific payloads | Common cases serve diagnostics; long tail is niche |
| DNS | Query name + basic A/AAAA answers | Full RR semantics, compression following, EDNS, DNSSEC | Audit engine needs `query_name`; rich records delegate |
| TLS | ClientHello/ServerHello metadata (SNI, ALPN, versions, ciphers) | Certificates, session tickets, full record parsing | Hello metadata serves filters/triage; deep TLS delegates |
| Checksums | IPv4/TCP/UDP validation | N/A | Must be native — operates on raw bytes |
| HTTP | First-packet method, URI, host, status_code, content_type | Full reassembly, chunked encoding, multipart | First-packet heuristic covers common cases; deep HTTP delegates |
| Layer spans | Byte offset tracking for hex dump | N/A | Must be native — produced during dissection |

**When to add a native dissector vs delegate to tshark:**

- **Add native** when the protocol's fields feed filters, audit heuristics, stream tracking, or MCP tool results that need typed access.
- **Delegate to tshark** when you need reassembly, deep payload inspection, or broad protocol identification that would require disproportionate parser investment.
- **Split ownership** when a protocol has a simple base header (keep native) and complex extensions (delegate). DNS and TLS are examples of this pattern.

## 6. Extension Points

### Adding a New Protocol

1. **Create the layer struct** in `crates/fireshark-core/src/layer.rs`:
   ```rust
   pub struct DnsLayer {
       pub transaction_id: u16,
       pub query_count: u16,
       // ...
   }
   ```

2. **Add a variant** to the `Layer` enum and update `Layer::name()`:
   ```rust
   pub enum Layer {
       // ...
       Dns(DnsLayer),
   }
   ```

3. **Create the dissector module** in `crates/fireshark-dissectors/src/dns.rs` following the dissector pattern:
   - Define constants (`IP_PROTOCOL` or `UDP_PORT`)
   - Implement `parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError>`
   - Explicit bounds checks before every slice access
   - Return `DecodeError::Truncated` or `DecodeError::Malformed`

4. **Wire the dissector** into `decode_packet()` in `crates/fireshark-dissectors/src/lib.rs` by adding a match arm in the transport dispatch.

5. **Add fixture files** to `fixtures/bytes/` with handcrafted binary data for unit tests.

6. **Update the filter evaluator** in `crates/fireshark-filter/src/evaluate.rs` to resolve fields from the new layer (e.g., `dns.id`, `dns.qcount`).

7. **Run `just check`** to verify formatting, clippy, and all tests pass.

### Adding a New CLI Command

1. **Add a variant** to the `Command` enum in `crates/fireshark-cli/src/main.rs`:
   ```rust
   enum Command {
       Summary { /* ... */ },
       Detail { /* ... */ },
       Stats { path: PathBuf },
   }
   ```

2. **Create the module** (e.g., `crates/fireshark-cli/src/stats.rs`) with a `pub fn run(path: &Path) -> Result<(), Box<dyn Error>>` entry point.

3. **Wire it** in `main()`:
   ```rust
   Command::Stats { path } => stats::run(&path)?,
   ```

4. **Add integration tests** in `crates/fireshark-cli/tests/` using `assert_cmd`.

### Adding a New MCP Tool

1. **Define request/response types** in `crates/fireshark-mcp/src/server.rs` (request struct with `Serialize`, `Deserialize`, `JsonSchema`) and `crates/fireshark-mcp/src/model.rs` (response view struct).

2. **Add the business logic** to the appropriate module (`query.rs`, `audit.rs`, or a new module).

3. **Add a method** to `ToolService` in `crates/fireshark-mcp/src/tools.rs`.

4. **Add the tool endpoint** in the `#[tool_router]` impl block in `server.rs`:
   ```rust
   #[tool(description = "Description of new tool")]
   async fn new_tool(
       &self,
       Parameters(request): Parameters<NewToolRequest>,
   ) -> McpResult<NewToolResponse> {
       self.tools.new_tool(/* ... */).await.map(Json).map_err(tool_error)
   }
   ```

### Adding a New Filter Field

1. **Add a match arm** in `resolve_layer_field()` in `crates/fireshark-filter/src/evaluate.rs`:
   ```rust
   ("dns.id", Layer::Dns(l)) => Some(FieldValue::Integer(u64::from(l.transaction_id))),
   ```

2. **If the field introduces a new value type**, add it to the `FieldValue` enum and update `compare_values()`.

3. **Add tests** using fixture files that exercise the new field in filter expressions.

## 7. Cross-Cutting Concerns

### Error Handling Strategy

Fireshark uses a two-tier error model:

| Error Type | Crate | Purpose | Propagation |
|-----------|-------|---------|-------------|
| `DecodeError` | `fireshark-dissectors` | Hard parse failure (truncated Ethernet, malformed IPv4 version) | Returned as `Err` from `decode_packet` only for Ethernet failures |
| `DecodeIssue` | `fireshark-core` | Soft decode problem at an inner layer | Collected in `Packet.issues`, never prevents packet creation |
| `CaptureError` | `fireshark-file` | File I/O or format error | Propagated through `CaptureReader` iterator |
| `PipelineError<F, D>` | `fireshark-core` | Wraps either frame-source or decode errors | Propagated through `Pipeline` iterator |
| `FilterError` | `fireshark-filter` | Parse-time filter syntax error | Returned from `parse()` |
| `SessionError` | `fireshark-mcp` | Session management failure (not found, limit reached) | Mapped to MCP `ErrorData` |
| `ToolError` | `fireshark-mcp` | Tool-level errors wrapping session/query failures | Mapped to MCP `ErrorData` |
| `AnalysisError` | `fireshark-mcp` | Capture loading failure (too large, IO, decode) | Wrapped in `SessionError` |

The critical distinction is `DecodeError` vs `DecodeIssue`. When IPv4 parsing fails inside an Ethernet frame, the error is **demoted** to a `DecodeIssue` and attached to the packet. The packet still contains the successfully parsed Ethernet layer. Only a failure at the outermost (Ethernet) layer produces a `DecodeError` that prevents `Packet` creation. This mirrors Wireshark's behavior: a packet with a malformed TCP header is still visible and inspectable up to the IP layer.

All error types use `thiserror` derive macros. No `unwrap()` or `expect()` on untrusted input.

### Testing Strategy

| Category | Location | Approach |
|----------|----------|----------|
| Dissector unit tests | `crates/fireshark-dissectors/src/*.rs` | `include_bytes!` with fixtures from `fixtures/bytes/` |
| File reader tests | `crates/fireshark-file/src/reader.rs` | pcap/pcapng files from `fixtures/smoke/` |
| Filter tests | `crates/fireshark-filter/src/evaluate.rs` | Build `DecodedFrame` from fixture bytes, apply filter expressions |
| CLI integration tests | `crates/fireshark-cli/tests/` | `assert_cmd` + `predicates` against the compiled binary |
| MCP integration tests | `crates/fireshark-mcp/tests/` | `assert_cmd` + `predicates` |
| Fuzz testing | `fuzz/fuzz_targets/` | Two cargo-fuzz targets: `fuzz_decode_packet`, `fuzz_capture_reader` |

Fixture files in `fixtures/bytes/` are handcrafted binary blobs (not extracted from captures) to ensure precise control over header fields and edge cases. New protocols add new fixture files rather than constructing bytes inline.

### Color and Formatting

All ANSI color output, protocol-to-color mapping, hex dump formatting, and timestamp rendering are confined to `fireshark-cli`. No other crate produces terminal output or depends on `colored`. The MCP crate uses `serde` serialization for structured JSON output.

## 8. Constraints and Limitations

### Current Constraints (Crawl Phase)

| Constraint | Detail |
|-----------|--------|
| **Ethernet-only link type** | `CaptureReader` rejects captures with non-Ethernet link types at open time. No support for raw IP, loopback, Wi-Fi radiotap, or other link layers. |
| **No live capture** | File-only ingestion. No `libpcap`/`npcap` binding, no `AF_PACKET`, no BPF. Planned for walk phase. |
| **No native TCP/IP reassembly** | Each packet is decoded independently by the native pipeline. Stream tracking identifies conversations by 5-tuple, but native TCP stream reassembly or IP fragment reassembly is not implemented (non-initial fragments skip transport decoding). The tshark backend provides TCP stream reassembly via `follow --payload` and `follow --http`. |
| **String filter operators** | Filter language supports `contains` (case-insensitive substring) and `matches` (regex) operators on any field type via string conversion. String-typed fields: `dns.qname`, `tls.sni`. |
| **No IPv6 CIDR filtering** | IPv4 CIDR (`ip.dst == 10.0.0.0/8`, `src 10.0.0.0/8`) is supported. IPv6 CIDR is not implemented -- only exact IPv6 address matching works. |
| **No MAC address filtering** | `eth.type` is filterable as an integer, but there is no `eth.src` or `eth.dst` field for MAC address comparison. |
| **Limited application-layer dissectors** | DNS over UDP port 53, TLS ClientHello/ServerHello over any TCP port, and HTTP first-packet parsing via ASCII signature heuristic are supported. No TCP-based DNS. |
| **MCP: offline only** | The MCP server loads entire captures into memory (up to 100,000 packets). No streaming, no live capture integration. |
| **MCP: 8 sessions, 15-min timeout** | Concurrency is capped at 8 sessions. Sessions expire after 15 minutes of inactivity. |
| **MCP: stdio transport only** | No HTTP, WebSocket, or SSE transport. |

## 9. Phase Roadmap

### Crawl (Complete -- v0.5.x)

Delivered the foundational offline analysis stack:

- **Complete:** pcap/pcapng reading with timestamp and original wire length extraction
- **Complete:** Protocol dissection for Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS ClientHello, TLS ServerHello, HTTP (11 protocols)
- **Complete:** Application-layer dispatch by port number (DNS over UDP port 53) and heuristic dispatch (TLS on any TCP port)
- **Complete:** DNS response parsing with A/AAAA answer records
- **Complete:** TLS handshake analysis: SNI extraction, cipher suites, ALPN, supported versions, signature algorithms, key share groups
- **Complete:** Color-coded CLI with commands: `summary`, `detail`, `stats`, `issues`, `audit`, `follow`
- **Complete:** Display filter language with lexer, parser, evaluator (including TLS filter fields, `tcp.stream`/`udp.stream`)
- **Complete:** MCP server with tools across session management, packet queries, streams, capture overview, and security audit
- **Complete:** TCP/UDP stream tracking: `StreamTracker` with canonical 5-tuple keys, `TrackingPipeline` iterator adapter, per-stream metadata
- **Complete:** Security audit heuristics: decode issues, unknown traffic, scan detection, suspicious ports, cleartext credential exposure, DNS tunneling detection, connection anomalies
- **Complete:** Fuzz testing infrastructure with two targets

### Walk (Active -- v0.6.0 + v0.6 + v0.8)

Adds backend abstraction, comparison, export, checksum validation, stream reassembly, and certificate extraction:

- **Complete:** tshark subprocess backend with differential testing (v0.6.0)
- **Complete:** JSON export -- `--json` flag on `summary`, `stats`, `issues`, `audit` for JSONL output (v0.6)
- **Complete:** Checksum validation -- IPv4 header, TCP, UDP checksums; `DecodeIssueKind::ChecksumMismatch`; zero checksums (NIC offload) skipped (v0.6)
- **Complete:** Capture comparison -- `diff` CLI command + `compare_captures` MCP tool (v0.6)
- **Complete:** tshark-backed TCP stream reassembly -- `follow --payload` (hex dump) and `follow --http` (HTTP request/response) (v0.8)
- **Complete:** TLS certificate extraction -- `get_certificates` MCP tool (subject CN, SAN DNS, org) (v0.8)
- **Complete:** `get_stream_payload` MCP tool -- reassembled TCP payload (v0.8)
- **Complete:** `supports_reassembly` capability in `BackendCapabilities` (v0.8)
- Planned: Live capture backends (platform-specific: `libpcap`, `AF_PACKET`, etc.)
- Planned: BPF compile-time capture filters (distinct from display filters)

### Run (Active -- v0.7 + v0.9)

Enables analyst workflows:

- **Complete:** String filter operators (`contains` for case-insensitive substring, `matches` for regex) on any field type via string conversion
- **Complete:** String-typed filter fields: `dns.qname`, `tls.sni`
- **Complete:** Audit profiles (`--profile security|dns|quality` on CLI, `profile` parameter on MCP `audit_capture`)
- **Complete:** Native HTTP first-packet parser with ASCII signature heuristic dispatch (GET, POST, HTTP/) — extracts method, URI, host, status_code, content_type (v0.9)
- **Complete:** HTTP filter fields: `http.method`, `http.uri`, `http.host`, `http.status_code`, `http.content_type` (v0.9)
- **Complete:** Finding escalation: `escalate_finding` MCP tool with notes, `[ESCALATED]` marker in CLI audit, `FindingView.escalated`/`notes` fields (v0.9)
- Planned: Advanced statistics (IO graphs, flow analysis, RTT estimation)
- Planned: Additional application-layer dissectors (TCP-based DNS, full TLS record parsing beyond handshake)

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
