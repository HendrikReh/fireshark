# Fireshark Roadmap

## Vision

Fireshark is an MCP-first packet analyzer. The LLM is the analyst — the MCP server gives it structured tools to explore captures, and the audit engine provides heuristic findings with evidence the LLM can drill into. Every new capability should give the LLM a new analytical dimension it couldn't access before.

**Design rule:** Public features must be accessible both via MCP (for LLM-driven workflows) and via CLI (for direct human use).

## Progression

1. **v0.3:** Packet intelligence — protocols, fields, filters, audit heuristics
2. **v0.4:** Application intelligence — what domains? what services?
3. **v0.5 (current):** Conversation intelligence — who talked to whom? how?
4. **v0.6:** Comparative intelligence — what changed? what's filtered via MCP?
5. **v0.7:** Content intelligence — what was said? what patterns?
6. **v1.0:** Real-time intelligence — what's happening now?

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

## v0.5 — Conversation intelligence (IN PROGRESS)

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
| Connection anomaly audit (SYN without SYN-ACK, reset storms, half-open) | Planned (Spec 2) |

## v0.6 — MCP as a security analyst platform

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| Capture comparison | New tool: `compare_captures(session_a, session_b)` — new hosts, ports, missing traffic | `diff <file1> <file2>` |
| Export tool | `export_packets(session_id, filter?, format)` as JSON | `--json` flag |
| Checksum validation (issue #8) | `audit_capture` flags corrupted packets; `get_packet` shows checksum status | Decode issues in detail |
| Certificate parsing (requires stream tracking from v0.5) | `get_packet` returns X.509 subject, issuer, validity | `detail` shows cert chain |

## v0.7 — String filters + extended audit

| Feature | MCP impact | CLI impact |
|---------|-----------|------------|
| String/regex filter operators (issue #10) | `search_packets` with `dns.qname contains "evil.com"` | `-f 'dns.qname contains "phishing"'` |
| HTTP basic dissector (requires stream tracking) | `get_packet` returns method, URI, Host, status | `detail` shows HTTP |
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

## Current metrics

| Metric | Value |
|--------|-------|
| Protocols | 10 (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS ClientHello, TLS ServerHello) |
| Tests | 306 |
| Source lines | ~8,100 |
| Crates | 6 |
| MCP tools | 17 |
| CLI commands | 6 (summary, detail, follow, stats, issues, audit) |
| Filter fields | 50+ |
| Audit heuristics | 6 |

---

**Version:** 0.4.0 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
