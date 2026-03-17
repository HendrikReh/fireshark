# Fireshark Roadmap

## Vision

Fireshark is an MCP-first packet analyzer. The LLM is the analyst — the MCP server gives it structured tools to explore captures, and the audit engine provides heuristic findings with evidence the LLM can drill into. Every new capability should give the LLM a new analytical dimension it couldn't access before.

## Progression

1. **v0.3 (current):** Packet intelligence — protocols, fields, filters, audit heuristics
2. **v0.4:** Application intelligence — what domains? what services?
3. **v0.5:** Conversation intelligence — who talked to whom? how?
4. **v0.6:** Comparative intelligence — what changed? what's filtered via MCP?
5. **v0.7:** Content intelligence — what was said? what patterns?
6. **v1.0:** Real-time intelligence — what's happening now?

---

## v0.4 — Deeper packet intelligence for the LLM

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| TLS ClientHello dissector | `get_packet` returns SNI, TLS version, cipher suites — LLM identifies domains in encrypted traffic | `detail` shows TLS handshake, filter: `tls.sni`, `-f "tls"` |
| DNS response parsing (issue #11, partial) | `get_packet` returns resolved addresses — LLM correlates DNS answers with connections | `detail` shows A/AAAA answers |
| Audit: cleartext credential exposure | `audit_capture` flags HTTP basic auth, FTP passwords, Telnet via port detection | LLM explains risk |
| Audit: DNS tunneling detection | Unusually long query names, high query volume to single domain, TXT record abuse | New finding category |

## v0.5 — Conversation-level analysis

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| TCP stream identity (`StreamTracker` in core) | New tool: `list_streams(session_id)` — stream tuples with packet counts, bytes, duration | `follow <file> <stream-id>` |
| New tool: `get_stream(session_id, stream_id)` | All packets in a conversation, ordered | Follow a connection |
| Audit: connection anomalies | Incomplete handshakes, reset storms, half-open connections | New finding category |
| Display filter: `tcp.stream == N` | Filter by conversation | CLI filter |
| Capture metadata in `describe_capture` | First/last timestamp, duration, total bytes, interface count | Summary header |
| `summarize_capture` tool (combined) | Single call replaces `describe_capture` + `summarize_protocols` + `top_endpoints` + `audit_capture` | Reduces LLM round-trips |

## v0.6 — MCP as a security analyst platform

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| Display filter in MCP search | `search_packets` accepts `-f` expressions instead of per-field params | Parity between CLI and MCP |
| Capture comparison | New tool: `compare_captures(session_a, session_b)` — new hosts, ports, missing traffic | `diff <file1> <file2>` |
| Export tool | `export_packets(session_id, filter?, format)` as JSON | `--json` flag |
| Checksum validation (issue #8) | `audit_capture` flags corrupted packets; `get_packet` shows checksum status | Decode issues in detail |

## v0.7 — String filters + extended audit

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| String/regex filter operators (issue #10) | `search_packets` with `dns.qname contains "evil.com"` | `-f 'dns.qname contains "phishing"'` |
| HTTP basic dissector (requires v0.5 stream tracking) | `get_packet` returns method, URI, Host, status | `detail` shows HTTP |
| Audit profiles | `audit_capture(session_id, profile="security")` — security, performance, compliance | `--audit-profile` flag |
| Finding escalation | `escalate_finding(finding_id, notes)` — builds investigation log | Investigation workflow |

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

**Version:** 0.3.0 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
