# Fireshark Roadmap

## Vision

Fireshark is an MCP-first packet analyzer. The LLM is the analyst — the MCP server gives it structured tools to explore captures, and the audit engine provides heuristic findings with evidence the LLM can drill into. Every new capability should give the LLM a new analytical dimension it couldn't access before.

**Design rules:**
- Public features must be accessible both via MCP (for LLM-driven workflows) and via CLI (for direct human use).
- Fireshark owns the product API surface. External tools (tshark) are optional backends and correctness oracles, not the product itself.

## Progression

1. **v0.3:** Packet intelligence — protocols, fields, filters, audit heuristics
2. **v0.4:** Application intelligence — what domains? what services?
3. **v0.5:** Conversation intelligence — who talked to whom? how?
4. **v0.6.0:** Backend abstraction — tshark as optional oracle, differential testing
5. **v0.6:** Security analyst platform — comparison, export, checksums, certificates
6. **v0.7:** Content intelligence — string filters, audit profiles
7. **v0.8:** Stream reassembly — tshark-backed payload reassembly, TLS certificate extraction
8. **v0.9 (current):** Application intelligence — HTTP first-packet parser, finding escalation
9. **v1.0:** Real-time intelligence — live capture

---

## v0.3 — Packet intelligence (COMPLETE)

Delivered: 10 protocol dissectors (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP with full RFC fields), Wireshark-style display filter language (hand-written recursive descent parser), color-coded CLI summary + detail with hex dump, MCP server with 14 tools (session management, packet queries, security audit), fuzz infrastructure.

## v0.4 — Application intelligence (COMPLETE)

| Feature | Status |
|---------|--------|
| TLS ClientHello + ServerHello dissectors (SNI, cipher suites, ALPN, supported versions, signature algorithms, key share) | **Done** |
| DNS response parsing (A/AAAA answer records) | **Done** |
| Audit: cleartext credential exposure (FTP, Telnet, HTTP, POP3, IMAP port detection) | **Done** |
| Audit: DNS tunneling detection (long labels, high unique query count, TXT queries) | **Done** |
| TCP application-layer dispatch (enables TLS on any port via heuristic) | **Done** |
| Dual-surface alignment: `stats`, `issues`, `audit` CLI commands | **Done** |
| MCP display filter expression support in `list_packets` and `search_packets` | **Done** |
| Wireshark sample capture regression tests (dns.cap, ipv4frags.pcap) | **Done** |

## v0.5 — Conversation intelligence (COMPLETE)

| Feature | Status |
|---------|--------|
| TCP/UDP stream identity (`StreamTracker` with canonical 5-tuple keys) | **Done** |
| `TrackingPipeline` — stream ID assignment during iteration | **Done** |
| `tcp.stream` / `udp.stream` display filter fields | **Done** |
| `follow` CLI command — show all packets in a conversation | **Done** |
| Stream count in `stats` output | **Done** |
| `list_streams` MCP tool — paginated stream metadata | **Done** |
| `get_stream` MCP tool — all packets in a conversation | **Done** |
| `summarize_capture` MCP tool — single-call capture overview | **Done** |
| Connection anomaly audit (incomplete handshake, RST storm, half-open) | **Done** |

## v0.6.0 — tshark backend (COMPLETE)

Optional `tshark` subprocess backend for offline capture analysis. The native Rust pipeline remains the default. tshark expands protocol coverage and provides a correctness oracle for differential testing.

| Feature | Status |
|---------|--------|
| `fireshark-backend` crate — shared backend abstraction: `BackendKind`, `BackendCapture`, capability model | **Done** |
| `fireshark-tshark` crate — tshark subprocess adapter: discovery, execution, TSV parsing, normalization | **Done** |
| Native backend adapter — wraps existing pipeline into `BackendCapture` | **Done** |
| Explicit `--backend native\|tshark` CLI flag for `summary` and `stats` commands | **Done** |
| Differential tests — compare native vs tshark output for stable packet facts | **Done** |
| Capability model — `supports_streams`, `supports_decode_issues`, `supports_native_filter`, etc. | **Done** |

**Design doc:** `docs/plans/2026-03-17-tshark-backend-design.md`
**Implementation plan:** `docs/plans/2026-03-17-tshark-backend.md`

## v0.6 — Security analyst platform (COMPLETE)

JSON export, checksum validation, and capture comparison delivered. Certificate parsing deferred to v0.7.

| Feature | Status |
|---------|--------|
| Capture comparison — `compare_captures` MCP tool, `diff <file1> <file2>` CLI command (new/missing hosts, protocols, ports) | **Done** |
| JSON export — `--json` flag on `summary`, `stats`, `issues`, `audit` (JSONL output, no color codes) | **Done** |
| Checksum validation — IPv4 header, TCP, UDP checksums verified; `DecodeIssueKind::ChecksumMismatch`; zero checksums (NIC offload) skipped | **Done** |
| Certificate parsing | **Deferred to v0.7** |

## v0.7 — String filters + audit profiles (COMPLETE)

| Feature | Status |
|---------|--------|
| String filter operators: `contains` (case-insensitive substring) and `matches` (regex) | **Done** |
| String-typed filter fields: `dns.qname`, `tls.sni` | **Done** |
| `regex` dependency added to `fireshark-filter` | **Done** |
| Works on any field type via string conversion | **Done** |
| Audit profiles: `--profile security\|dns\|quality` on CLI `audit` command | **Done** |
| MCP `audit_capture` accepts `profile` parameter | **Done** |
| Default (no profile) runs all heuristics | **Done** |

## v0.8 — Stream reassembly + certificate extraction (COMPLETE)

| Feature | Status |
|---------|--------|
| tshark-backed TCP stream reassembly via `follow --payload` (hex dump of reassembled payload) | **Done** |
| tshark-backed HTTP reassembly via `follow --http` (HTTP request/response) | **Done** |
| `get_stream_payload` MCP tool — reassembled TCP payload for a stream (requires tshark backend) | **Done** |
| `get_certificates` MCP tool — TLS certificate extraction: subject CN, SAN DNS names, organization (requires tshark backend) | **Done** |
| `supports_reassembly` capability in `BackendCapabilities` | **Done** |
| `follow_stream` method on backend for reassembly support | **Done** |

## v0.9 — Application intelligence (COMPLETE)

| Feature | Status |
|---------|--------|
| Native HTTP first-packet parser with ASCII signature heuristic dispatch (GET, POST, HTTP/) — extracts method, URI, host, status_code, content_type from first TCP packet without reassembly | **Done** |
| HTTP filter fields: `http.method`, `http.uri`, `http.host`, `http.status_code`, `http.content_type` (all support `contains`/`matches`) | **Done** |
| HTTP color: BrightCyan in CLI summary output | **Done** |
| `http` protocol keyword in display filter language | **Done** |
| Finding escalation: `escalate_finding` MCP tool with notes parameter | **Done** |
| `[ESCALATED]` marker in CLI audit output for escalated findings | **Done** |
| `FindingView` gains `escalated` and `notes` fields in MCP responses | **Done** |

## v1.0 — Walk phase: live capture

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| `CaptureSource` trait + libpcap backend | New tool: `start_live_capture(interface, filter?, max_packets)` | `fireshark live eth0` |
| BPF capture filter | Efficient pre-filtering before decode | `--capture-filter "port 443"` |

---

## Deferred past v1.0

| Feature | Reason |
|---------|--------|
| IP options / TCP options parsing (#9) | Low signal for LLM analysis |
| DNSSEC (#11) | Niche, LLM can't reason about crypto validation |
| Bitwise filter operators (#10) | Power-user feature the LLM won't use |
| IPv6 extension headers (#9) | Low frequency in most captures |
| MCP resources/prompts | Tools are sufficient for current workflows |

---

## Current metrics

| Metric | Value |
|--------|-------|
| Protocols | 11 (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS ClientHello, TLS ServerHello, HTTP) |
| Tests | 469 |
| Source lines | ~9,500 |
| Crates | 8 (fireshark-core, fireshark-file, fireshark-dissectors, fireshark-filter, fireshark-cli, fireshark-mcp, fireshark-backend, fireshark-tshark) |
| MCP tools | 21 |
| CLI commands | 7 (summary, detail, follow, stats, issues, audit, diff) |
| Filter fields | 50+ |
| Audit heuristics | 8 |

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
