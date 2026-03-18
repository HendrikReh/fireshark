# Fireshark User Guide

## Installation

Fireshark is built from source using the Rust toolchain.

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer (includes `cargo`)

### Build

```bash
git clone <repository-url>
cd fireshark
cargo build --release
```

The CLI binary is at `target/release/fireshark`. Copy it anywhere on your `PATH`:

```bash
cp target/release/fireshark /usr/local/bin/
```

## Quick Start

### Packet Summary

List all packets in a capture file with color-coded protocol output:

```bash
fireshark summary capture.pcap
```

Output format:

```
   1  2024-01-15T10:30:45.123Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
   2  2024-01-15T10:30:45.200Z  UDP    10.0.0.5:53214         -> 8.8.8.8:53               72
   3  2024-01-15T10:30:45.300Z  ARP    00:1a:2b:3c:4d:5e      -> ff:ff:ff:ff:ff:ff        42
```

Each line shows: packet number, timestamp (UTC), protocol, source, destination, and captured length in bytes.

### Packet Detail

Inspect a single packet with full layer decode and hex dump:

```bash
fireshark detail capture.pcap 1
```

Output:

```
Packet 1 . 54 bytes . 2024-01-15T10:30:45.123Z
-----------------------------------------------
> Ethernet
    Destination: 00:1a:2b:3c:4d:5e
    Source:      aa:bb:cc:dd:ee:ff
    EtherType:   0x0800 (IPv4)
> IPv4
    Source:      192.0.2.10
    Destination: 198.51.100.20
    TTL: 64  Protocol: 6 (TCP)  ID: 0x1234
    DSCP: 0  ECN: 0  Checksum: 0xabcd
> TCP
    51514 -> 443  Seq: 100  Ack: 0  [SYN]  Win: 65535
    Data Offset: 5 (20 bytes)
--- Hex Dump ----------------------------------
0000  00 1a 2b 3c 4d 5e aa bb  cc dd ee ff 08 00 45 00  ..+<M^........E.
0010  00 28 12 34 40 00 40 06  ab cd c0 00 02 0a c6 33  .(.4@.@........3
...
  # Ethernet  # IPv4  # TCP
```

Each byte in the hex dump is colored by its protocol layer.

### Follow a Stream

Show all packets in a TCP/UDP conversation by stream ID:

```bash
fireshark follow capture.pcap 0
```

Output:

```
Stream 0: TCP 192.0.2.10:51514 ↔ 198.51.100.20:443
3 packets, 162 bytes, duration 0.200s
──────────────────────────────────────
   1  2024-01-15T10:30:45.123Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
   2  2024-01-15T10:30:45.200Z  TCP    198.51.100.20:443      -> 192.0.2.10:51514         54
   3  2024-01-15T10:30:45.300Z  TCP    192.0.2.10:51514       -> 198.51.100.20:443        54
```

The stream header shows the conversation's protocol, endpoints, packet/byte count, and duration. Use `fireshark stats` to discover available stream IDs.

#### Stream Reassembly (requires tshark)

The `follow` command supports reassembled stream views via the tshark backend:

```bash
# Show reassembled TCP payload as hex dump
fireshark follow capture.pcap 0 --payload

# Show HTTP request/response for a stream
fireshark follow capture.pcap 0 --http
```

The `--payload` flag shows the reassembled TCP payload as a hex dump, reconstructing the byte stream from individual TCP segments. The `--http` flag shows the HTTP request and response for HTTP streams. Both flags require tshark to be installed.

### TLS Certificate Extraction

TLS certificate details can be extracted from captures using the `get_certificates` MCP tool (requires tshark backend). This extracts:

- Subject Common Name (CN)
- Subject Alternative Name (SAN) DNS entries
- Organization name

This is useful for identifying which services are being contacted and verifying certificate validity during security audits.

### Compare Two Captures

Compare a baseline and suspect capture to find new or missing hosts, protocols, and ports:

```bash
fireshark diff baseline.pcap suspect.pcap
```

The output shows which hosts, protocols, and ports appeared in one capture but not the other — useful for detecting changes between a known-good baseline and a new capture.

### JSON Export

Add `--json` to `summary`, `stats`, `issues`, or `audit` to get machine-readable output. Each line is one JSON object (JSONL format), with no ANSI color codes:

```bash
# JSONL packet summaries
fireshark summary capture.pcap --json

# JSONL statistics
fireshark stats capture.pcap --json

# JSONL decode issues
fireshark issues capture.pcap --json

# JSONL audit findings
fireshark audit capture.pcap --json
```

This is useful for piping into `jq`, feeding into scripts, or integrating with other tools.

### Checksum Validation

Fireshark validates IPv4 header, TCP, and UDP checksums during dissection. If a checksum does not match the computed value, a `ChecksumMismatch` decode issue is recorded on the packet. Zero checksums (common when NIC offload is enabled, meaning the checksum was computed by hardware after capture) are skipped — they are not flagged as errors.

Checksum issues appear in the `issues` command output and in `detail` view decode issue indicators.

### Backend Selection

fireshark supports two analysis backends. The choice affects which features are available and how broad protocol coverage is.

#### `--backend native` (default)

The native backend uses fireshark's built-in Rust dissectors. This is the default and provides the full feature set:

- Deep protocol analysis with typed field extraction (10 protocols)
- Security audit heuristics (scan detection, DNS tunneling, cleartext credentials, etc.)
- TCP/UDP stream tracking with `follow` command and `tcp.stream`/`udp.stream` filters
- Display filter evaluation on all supported fields (`tcp.flags.syn and ip.ttl > 64`)
- Color-coded hex dump with per-layer byte spans in `detail` view
- Zero external dependencies -- works without Wireshark installed

```bash
fireshark summary capture.pcap                    # native is the default
fireshark summary --backend native capture.pcap   # explicit
fireshark audit capture.pcap                      # audit requires native
fireshark follow capture.pcap 0                   # follow requires native
```

#### `--backend tshark`

The tshark backend delegates analysis to Wireshark's `tshark` command-line tool. It provides broader protocol recognition (3,000+ protocols) but with reduced feature depth:

- Protocol identification and packet summaries work for all protocols tshark supports
- Capture statistics (`stats` command) work
- **Stream reassembly is available** -- `follow --payload` (hex dump) and `follow --http` (HTTP request/response)
- **TLS certificate extraction is available** -- `get_certificates` MCP tool
- Stream tracking (native) is **not available** -- no `tcp.stream`/`udp.stream` filters
- Security audit is **not available** -- no `audit` command
- Display filters are **not available** -- fireshark's filter engine requires typed native layers
- Detail hex dump is **not available** -- tshark does not expose per-layer byte offsets

```bash
fireshark summary --backend tshark capture.pcap
fireshark stats --backend tshark capture.pcap
```

#### When to use each

| Scenario | Recommended backend |
|----------|-------------------|
| Deep analysis of TCP/IP traffic | `native` |
| Security audit of a capture | `native` |
| Following a TCP/UDP conversation | `native` |
| Filtering packets by field values | `native` |
| Inspecting packet bytes with hex dump | `native` |
| Reassembled TCP stream payload | `tshark` |
| HTTP request/response extraction | `tshark` |
| TLS certificate extraction | `tshark` |
| Triage of a capture with many unknown protocols | `tshark` |
| Quick protocol distribution overview | either |
| Validating fireshark output against Wireshark | `tshark` |

Note: tshark must be installed on your system for `--backend tshark` to work. If tshark is not found, fireshark will report an error. See the operations guide for tshark discovery details.

### Capture Statistics

```bash
fireshark stats capture.pcap
```

Shows packet count, stream count, capture duration, protocol distribution, and top endpoints.

### Filtered Summary

Apply a display filter to show only matching packets:

```bash
fireshark summary capture.pcap -f "tcp and port 443"
```

## Display Filters

Fireshark supports a Wireshark-style display filter language. Pass a filter expression with the `-f` flag on the summary command.

### Protocol Presence

Match packets containing a specific protocol:

| Expression | Matches |
|-----------|---------|
| `tcp` | Any packet with a TCP layer |
| `udp` | Any packet with a UDP layer |
| `arp` | Any packet with an ARP layer |
| `icmp` | Any packet with an ICMP layer |
| `dns` | Any packet with a DNS layer |
| `tls` | Any packet with a TLS layer (ClientHello or ServerHello) |
| `ipv4` | Any packet with an IPv4 layer |
| `ipv6` | Any packet with an IPv6 layer |
| `ethernet` | Any packet with an Ethernet layer |

### Boolean Operators

Combine expressions with `and`, `or`, and `not`:

| Operator | Example | Meaning |
|----------|---------|---------|
| `and` | `tcp and udp` | Both must be present |
| `or` | `tcp or udp` | Either must be present |
| `not` | `not arp` | ARP must not be present |
| `()` | `(tcp or udp) and port 53` | Grouping for precedence |

Operator precedence (highest to lowest): `not`, `and`, `or`. Use parentheses to override.

### Shorthands

Convenience expressions that expand to common multi-field checks:

| Shorthand | Equivalent | Meaning |
|-----------|-----------|---------|
| `port 443` | `tcp.port == 443 or udp.port == 443` | TCP or UDP port, either direction |
| `src 192.168.1.2` | `ip.src == 192.168.1.2` | Source IP address |
| `dst 10.0.0.0/8` | `ip.dst == 10.0.0.0/8` | Destination IP with CIDR |
| `host 192.168.1.1` | `ip.src == 192.168.1.1 or ip.dst == 192.168.1.1` | Source or destination IP |

### Field Comparisons

Compare specific protocol fields against values:

```
<field> <operator> <value>
```

#### Comparison Operators

| Operator | Meaning |
|----------|---------|
| `==` | Equal |
| `!=` | Not equal |
| `>` | Greater than |
| `<` | Less than |
| `>=` | Greater than or equal |
| `<=` | Less than or equal |

#### String Operators

| Operator | Meaning |
|----------|---------|
| `contains` | Case-insensitive substring match |
| `matches` | Regular expression match (regex crate syntax) |

String operators work on any field type. Non-string fields are converted to their string representation before matching.

```bash
# Find DNS queries for a specific domain (case-insensitive)
fireshark summary capture.pcap -f 'dns.qname contains "evil.com"'

# Find TLS connections to CDN hosts using regex
fireshark summary capture.pcap -f 'tls.sni matches "^cdn\d+\.example\.com"'

# Works on non-string fields too (via string conversion)
fireshark summary capture.pcap -f 'ip.src contains "192.168"'
```

#### Supported Fields

**Frame fields:**

| Field | Type | Description |
|-------|------|-------------|
| `frame.len` | integer | Original wire length |
| `frame.cap_len` | integer | Captured length |

**Ethernet fields:**

| Field | Type | Description |
|-------|------|-------------|
| `eth.type` | integer | EtherType value |

**IPv4 fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | address | Source IP (also matches IPv6) |
| `ip.dst` | address | Destination IP (also matches IPv6) |
| `ip.ttl` | integer | Time to live |
| `ip.id` | integer | Identification |
| `ip.proto` | integer | Protocol number |
| `ip.dscp` | integer | DSCP value |
| `ip.ecn` | integer | ECN value |
| `ip.checksum` | integer | Header checksum |
| `ip.flags.df` | boolean | Don't Fragment flag |
| `ip.flags.mf` | boolean | More Fragments flag |
| `ip.frag_offset` | integer | Fragment offset |

**IPv6 fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | address | Source IP (dual-stack, shared with IPv4) |
| `ip.dst` | address | Destination IP (dual-stack, shared with IPv4) |
| `ipv6.hlim` | integer | Hop limit |
| `ipv6.flow` | integer | Flow label |
| `ipv6.tc` | integer | Traffic class |
| `ipv6.nxt` | integer | Next header |

**TCP fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tcp.srcport` | integer | Source port |
| `tcp.dstport` | integer | Destination port |
| `tcp.port` | integer | Either source or destination port |
| `tcp.seq` | integer | Sequence number |
| `tcp.ack` | integer | Acknowledgment number |
| `tcp.window` | integer | Window size |
| `tcp.hdr_len` | integer | Header length in bytes |
| `tcp.flags.syn` | boolean | SYN flag |
| `tcp.flags.ack` | boolean | ACK flag |
| `tcp.flags.fin` | boolean | FIN flag |
| `tcp.flags.rst` | boolean | RST flag |
| `tcp.flags.psh` | boolean | PSH flag |
| `tcp.flags.urg` | boolean | URG flag |
| `tcp.flags.ece` | boolean | ECE flag |
| `tcp.flags.cwr` | boolean | CWR flag |
| `tcp.stream` | integer | TCP stream ID (conversation number, assigned by `TrackingPipeline`) |

**UDP fields:**

| Field | Type | Description |
|-------|------|-------------|
| `udp.srcport` | integer | Source port |
| `udp.dstport` | integer | Destination port |
| `udp.port` | integer | Either source or destination port |
| `udp.length` | integer | UDP datagram length |
| `udp.stream` | integer | UDP stream ID (conversation number, assigned by `TrackingPipeline`) |

**ICMP fields:**

| Field | Type | Description |
|-------|------|-------------|
| `icmp.type` | integer | ICMP message type |
| `icmp.code` | integer | ICMP message code |

**DNS fields:**

| Field | Type | Description |
|-------|------|-------------|
| `dns.id` | integer | Transaction ID |
| `dns.qr` | boolean | Query/response flag (true=response) |
| `dns.opcode` | integer | Operation code |
| `dns.qcount` | integer | Question count |
| `dns.acount` | integer | Answer count |
| `dns.qtype` | integer | Query type (1=A, 28=AAAA, etc.) |
| `dns.qname` | string | Query name (e.g., "example.com") |
| `dns.rcode` | integer | Response code (0=NOERROR, 3=NXDOMAIN, etc.) |

**TLS fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tls.handshake.type` | integer | Handshake type (1=ClientHello, 2=ServerHello) |
| `tls.record_version` | integer | TLS record layer version |
| `tls.client_version` | integer | ClientHello version (ClientHello only) |
| `tls.selected_version` | integer | Selected version from supported_versions extension (ServerHello only) |
| `tls.cipher_suite` | integer | Selected cipher suite (ServerHello only) |
| `tls.sni` | string | Server Name Indication (ClientHello only) |

**ARP fields:**

| Field | Type | Description |
|-------|------|-------------|
| `arp.opcode` | integer | ARP operation (1=request, 2=reply) |
| `arp.spa` | address | Sender protocol address |
| `arp.tpa` | address | Target protocol address |

#### CIDR Notation

IP address fields support CIDR subnet matching:

```
ip.src == 10.0.0.0/8
ip.dst == 192.168.1.0/24
dst 172.16.0.0/12
```

#### Boolean Field Checks

Boolean fields (TCP flags, IP flags) can be compared against `true` or `false`:

```
tcp.flags.syn == true
ip.flags.df == true
tcp.flags.ack == false
```

Or used as bare expressions for protocol presence checks.

## Color Coding

Summary output is color-coded by the highest-layer protocol:

| Protocol | Color |
|----------|-------|
| TCP | Green |
| UDP | Blue |
| ARP | Yellow |
| ICMP | Cyan |
| DNS | Magenta |
| TLS | Bright Green |
| Ethernet, IPv4, IPv6 | White |
| Unknown / other | Red |

Colors follow Wireshark conventions. The hex dump in the detail view colors each byte by its protocol layer, with a legend at the bottom.

## Packet Detail

The `detail` command shows three sections for a single packet:

### Header

```
Packet 1 . 54 bytes . 2024-01-15T10:30:45.123Z
```

Packet number, captured length, and UTC timestamp.

### Layer Tree

Each decoded protocol layer is shown with all extracted fields:

- **Ethernet** -- destination MAC, source MAC, EtherType
- **ARP** -- operation, sender IP, target IP
- **IPv4** -- source, destination, TTL, protocol, ID, flags (DF/MF), DSCP, ECN, checksum
- **IPv6** -- source, destination, next header, hop limit, traffic class, flow label
- **TCP** -- ports, sequence, acknowledgment, flags (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), window, data offset
- **UDP** -- ports, length
- **ICMP** -- type (with name), code, and type-specific detail (echo ID/seq, next hop MTU)
- **DNS** -- transaction ID, query/response, opcode, question count, answer count, query name, query type, A/AAAA answer records
- **TLS ClientHello** -- record version, client version, cipher suites, SNI, ALPN, supported versions, signature algorithms, key share groups
- **TLS ServerHello** -- record version, server version, cipher suite, selected version, ALPN, key share group

### Decode Issue Indicators

If a packet has decode issues, they appear after the layer tree:

```
! Truncated at offset 34
! Malformed at offset 14
```

### Hex Dump

A 16-bytes-per-line hex dump with:

- Offset column (hex)
- Hex bytes colored by protocol layer
- ASCII column (printable characters, dots for non-printable)
- Legend mapping colors to protocol names

## MCP Server

The MCP server provides LLM-driven capture analysis over stdio transport.

### Starting the Server

```bash
# From source
cargo run -p fireshark-mcp

# Or the release binary
fireshark-mcp
```

The server communicates over stdin/stdout using the Model Context Protocol.

### Connecting to Claude Code

```bash
# Build the release binary
cargo build -p fireshark-mcp --release

# Register with Claude Code
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

Once connected, Claude can analyze captures directly:

> "Open `/tmp/traffic.pcap` and audit it for security issues"

### Connecting to Codex

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

### Example Analysis Workflow

A typical LLM-driven session through MCP:

1. `open_capture({ path: "/tmp/traffic.pcap" })` → session_id + protocol breakdown
2. `summarize_capture({ session_id })` → protocols, endpoints, streams, findings
3. `audit_capture({ session_id })` → security findings with evidence
4. `get_packet({ session_id, packet_index: 42 })` → full layer decode
5. `list_packets({ session_id, filter: "tls and tls.handshake.type == 1" })` → TLS ClientHellos
6. `get_stream({ session_id, stream_id: 5 })` → follow a conversation
7. `close_capture({ session_id })` → free resources

### Generic MCP Clients

Any MCP-compatible client can connect by spawning the binary as a subprocess over stdio.

### Tool Reference

#### Session Management

| Tool | Parameters | Returns |
|------|-----------|---------|
| `open_capture` | `path` (string), optional `max_packets` (integer, default 100000, max 1000000) | Session ID, packet count, protocol summary |
| `describe_capture` | `session_id` (string) | Capture metadata, protocol breakdown, top endpoints |
| `close_capture` | `session_id` (string) | Confirmation |

#### Packet Queries

| Tool | Parameters | Returns |
|------|-----------|---------|
| `list_packets` | `session_id`, optional `offset`, `limit`, `protocol`, `has_issues` | Paginated packet summaries |
| `get_packet` | `session_id`, `packet_number` | Full packet detail with all layer fields |
| `search_packets` | `session_id`, search criteria (protocol, address, port, text, issues) | Matching packet list |
| `list_decode_issues` | `session_id`, optional `kind` filter | Paginated decode issues |
| `summarize_protocols` | `session_id` | Protocol distribution table |
| `top_endpoints` | `session_id` | Most active endpoints by packet count |

#### Streams

| Tool | Parameters | Returns |
|------|-----------|---------|
| `list_streams` | `session_id`, optional `offset`, `limit` | Paginated TCP/UDP conversation metadata |
| `get_stream` | `session_id`, `stream_id` | Stream metadata plus all packets in the conversation |
| `get_stream_payload` | `session_id`, `stream_id` | Reassembled TCP payload hex dump (requires tshark backend) |

#### Capture Overview

| Tool | Parameters | Returns |
|------|-----------|---------|
| `summarize_capture` | `session_id` | Single-call summary: packets, streams, protocols, endpoints, timestamps, findings |

#### Comparison

| Tool | Parameters | Returns |
|------|-----------|---------|
| `compare_captures` | `session_id_a`, `session_id_b` | New/missing hosts, protocols, and ports between two captures |

#### Security Audit

| Tool | Parameters | Returns |
|------|-----------|---------|
| `audit_capture` | `session_id`, optional `profile` (`"security"`, `"dns"`, `"quality"`) | Heuristic security analysis results (filtered by profile if specified) |
| `list_findings` | `session_id` | Audit findings with severity and evidence |
| `explain_finding` | `session_id`, `finding_id` | Detailed explanation of a specific finding |

#### TLS

| Tool | Parameters | Returns |
|------|-----------|---------|
| `get_certificates` | `session_id` | TLS certificate details: subject CN, SAN DNS names, organization (requires tshark backend) |

### Workflow Example

A typical MCP session:

```
Client: open_capture(path: "/tmp/suspect.pcap")
Server: { session_id: "abc123", packets: 1500, protocols: { TCP: 1200, UDP: 250, ARP: 50 } }

Client: describe_capture(session_id: "abc123")
Server: { packet_count: 1500, duration: "5m30s", top_endpoints: [...] }

Client: audit_capture(session_id: "abc123")
Server: { findings: [{ id: "f1", severity: "high", title: "Port scan detected", ... }] }

Client: explain_finding(session_id: "abc123", finding_id: "f1")
Server: { detail: "Sequential SYN packets to ports 22, 80, 443, 8080 from 10.0.0.5...", evidence: [...] }

Client: search_packets(session_id: "abc123", address: "10.0.0.5")
Server: { packets: [{ number: 1, protocol: "TCP", ... }, ...] }

Client: close_capture(session_id: "abc123")
Server: { status: "closed" }
```

### Constraints

- Stdio transport only -- no HTTP or WebSocket
- Offline captures only -- no live packet capture
- Default packet limit: 100,000 (configurable via `max_packets` parameter in `open_capture`, capped at 1,000,000)
- Maximum 8 concurrent sessions
- Sessions expire after 15 minutes of inactivity

### Capture Size Limits

| Surface | Packet limit | Behavior |
|---------|-------------|----------|
| `summary`, `detail`, `stats`, `issues`, `follow` | None -- streaming | Processes any capture size |
| `audit` CLI command | 100,000 (configurable via `--max-packets`) | Rejects capture if exceeded |
| MCP `open_capture` | 100,000 (configurable via `max_packets` parameter) | Rejects capture if exceeded |
| tshark backend | None | Loads whatever tshark outputs |

The streaming CLI commands (`summary`, `detail`, `stats`, `issues`, `follow`) iterate packets one at a time and have no memory limit. The `audit` command and MCP tools load all packets into memory for indexing and cross-referencing, so they enforce a configurable packet limit (default 100,000).

To analyze larger captures:

```bash
# CLI: increase the limit for audit
fireshark audit --max-packets 500000 large-capture.pcap
```

For MCP, pass `max_packets` when opening:
```json
{ "path": "/tmp/large.pcap", "max_packets": 500000 }
```

## Examples

### Find All SYN Packets (Connection Initiations)

```bash
fireshark summary capture.pcap -f "tcp.flags.syn == true and tcp.flags.ack == false"
```

### Show Only DNS Traffic

```bash
fireshark summary capture.pcap -f "dns"
```

### DNS Queries Only (Not Responses)

```bash
fireshark summary capture.pcap -f "dns and not dns.qr"
```

### DNS by Transaction ID

```bash
fireshark summary capture.pcap -f "dns.id == 0x1234"
```

### DNS A Record Queries

```bash
fireshark summary capture.pcap -f "dns.qtype == 1"
```

### Filter by Subnet

```bash
fireshark summary capture.pcap -f "src 10.0.0.0/8"
fireshark summary capture.pcap -f "dst 192.168.0.0/16"
```

### Inspect a Specific Packet

```bash
fireshark detail capture.pcap 5
```

### Show Only ARP Traffic

```bash
fireshark summary capture.pcap -f "arp"
```

### Find RST Packets (Connection Resets)

```bash
fireshark summary capture.pcap -f "tcp.flags.rst == true"
```

### Traffic Between Two Hosts

```bash
fireshark summary capture.pcap -f "host 192.168.1.10 and host 192.168.1.20"
```

### ICMP Only (Pings, Errors)

```bash
fireshark summary capture.pcap -f "icmp"
```

### High TTL Packets

```bash
fireshark summary capture.pcap -f "ip.ttl > 200"
```

### TCP Traffic on Non-Standard Ports

```bash
fireshark summary capture.pcap -f "tcp and not port 80 and not port 443 and not port 22"
```

### Show Fragmented Packets

```bash
fireshark summary capture.pcap -f "ip.flags.mf == true"
```

### UDP Traffic Excluding DNS

```bash
fireshark summary capture.pcap -f "udp and not port 53"
```

### Show All TLS Handshakes

```bash
fireshark summary capture.pcap -f "tls"
```

### TLS ClientHello Only

```bash
fireshark summary capture.pcap -f "tls.handshake.type == 1"
```

### TLS ServerHello Only

```bash
fireshark summary capture.pcap -f "tls.handshake.type == 2"
```

### TLS by Cipher Suite

```bash
fireshark summary capture.pcap -f "tls.cipher_suite == 0x1301"
```

### Filter by Stream ID

```bash
# Show all packets in TCP conversation 0
fireshark summary capture.pcap -f "tcp.stream == 0"

# Show all packets in UDP conversation 1
fireshark summary capture.pcap -f "udp.stream == 1"
```

### Follow a Specific Stream

```bash
fireshark follow capture.pcap 0
```

### String Filters

```bash
# Case-insensitive substring match on DNS query name
fireshark summary capture.pcap -f 'dns.qname contains "evil"'

# Regex match on TLS SNI
fireshark summary capture.pcap -f 'tls.sni matches ".*\.example\.com"'

# String conversion: works on any field
fireshark summary capture.pcap -f 'ip.dst contains "10.0"'
```

### Audit Profiles

```bash
# Run all heuristics (default)
fireshark audit capture.pcap

# Security-focused audit only
fireshark audit --profile security capture.pcap

# DNS-focused audit only
fireshark audit --profile dns capture.pcap

# Quality-focused audit only
fireshark audit --profile quality capture.pcap
```

---

**Version:** 0.8.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
