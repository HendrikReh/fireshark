# Fireshark Operations Guide

## Deployment

Fireshark is a statically-linked Rust binary with no runtime dependencies. Build and ship:

```bash
# Build the CLI binary
cargo build --release -p fireshark-cli

# Build the MCP server binary
cargo build --release -p fireshark-mcp
```

Release binaries are located at:

- `target/release/fireshark` -- CLI tool
- `target/release/fireshark-mcp` -- MCP server

Copy the binary to the target host. No installer, no package manager, no runtime needed.

### Build Requirements

- Rust toolchain 1.85 or newer
- `cargo` (ships with Rust)
- No C dependencies, no system libraries beyond libc

## Runtime Requirements

| Requirement | CLI | MCP Server |
|-------------|-----|------------|
| Config files | None | None |
| Database | None | None |
| Network access | None | None |
| Filesystem | Read access to capture files | Read access to capture files |
| stdin/stdout | Normal terminal I/O | MCP stdio transport |
| Environment variables | None required | None required |

Fireshark is a zero-configuration tool. Point it at a pcap/pcapng file and it works.

### Optional: tshark Runtime Dependency

tshark (Wireshark's command-line tool) is **not required** for basic operation. Fireshark's native Rust dissectors handle all analysis by default.

tshark is required **only** when `--backend tshark` is explicitly requested:

```bash
fireshark summary --backend tshark capture.pcap
```

**Discovery order:**

1. `tshark` on the system `PATH`
2. `/Applications/Wireshark.app/Contents/MacOS/tshark` (macOS Wireshark.app bundle)

**Minimum version:** 3.0.0. Fireshark checks the tshark version at invocation time and rejects older versions.

If tshark is not found when `--backend tshark` is requested, fireshark will exit with an error message indicating that tshark was not found. This does not affect `--backend native` (the default), which has zero external dependencies.

## CLI Operation

The CLI has 7 commands:

```bash
# List all packets with color-coded protocol summary
fireshark summary <capture.pcap> [-f "filter expression"]

# Show detailed decode of a single packet (1-indexed)
fireshark detail <capture.pcap> <packet-number>

# Show all packets in a TCP/UDP conversation by stream ID
fireshark follow <capture.pcap> <stream-id>

# Capture statistics: packets, streams, duration, protocols, endpoints
fireshark stats <capture.pcap>

# List decode issues
fireshark issues <capture.pcap>

# Run security audit heuristics
fireshark audit <capture.pcap>

# Compare two captures (new/missing hosts, protocols, ports)
fireshark diff <baseline.pcap> <suspect.pcap>

# JSON export (JSONL output, no color codes) — supported on summary, stats, issues, audit
fireshark summary <capture.pcap> --json
fireshark stats <capture.pcap> --json
fireshark issues <capture.pcap> --json
fireshark audit <capture.pcap> --json
```

Exit codes:

- `0` -- success
- `1` -- error (invalid file, bad filter expression, packet not found)

Decode warnings (truncated/malformed packets) are printed to stderr but do not cause a non-zero exit.

## MCP Server Operation

The MCP server runs over stdio transport. It does not listen on a network socket. For installation and tool reference, see [MCP Server Reference](../references/mcp-server.md).

```bash
fireshark-mcp
```

Connect from any MCP-compatible client (e.g., Claude Desktop, an LLM agent) by wiring its stdin/stdout to the server process.

### Session Limits

| Parameter | Value |
|-----------|-------|
| Transport | stdio only (no HTTP, no WebSocket) |
| Max concurrent sessions | 8 |
| Max packets per capture | 100,000 |
| Idle session timeout | 15 minutes |

A session is created by calling `open_capture` with a file path. The server returns a `session_id` that must be passed to all subsequent queries. Sessions are closed explicitly with `close_capture` or automatically after 15 minutes of inactivity.

### MCP Tool Families (21 tools)

| Family | Tools |
|--------|-------|
| Session | `open_capture`, `describe_capture`, `close_capture` |
| Packet queries | `list_packets`, `get_packet`, `search_packets`, `list_decode_issues`, `summarize_protocols`, `top_endpoints` |
| Streams | `list_streams`, `get_stream`, `get_stream_payload` |
| Capture overview | `summarize_capture` |
| Comparison | `compare_captures` |
| Audit | `audit_capture`, `list_findings`, `explain_finding`, `escalate_finding` |
| TLS | `get_certificates` |

## Resource Usage

### Memory

Memory consumption is proportional to capture file size. The entire decoded capture is held in memory for the duration of a session (MCP) or command (CLI).

Rough guideline: expect 2-4x the pcap file size in peak memory usage due to decoded layer structures and metadata.

### CPU

CPU usage is bound during the decode phase. Parsing is single-threaded per capture. For the CLI, CPU usage spikes during file read and decode, then drops to zero during output. The MCP server decodes once on `open_capture` and serves queries from the in-memory representation.

### Disk

No temporary files. No log files. No cache. The only disk access is reading the input capture file.

## Limitations

| Limitation | Detail |
|------------|--------|
| Offline only | No live capture support. Fireshark reads pcap and pcapng files only. |
| Ethernet only | Only the Ethernet link layer is supported. Wi-Fi (radiotap), PPP, raw IP, and other link types are rejected. |
| Protocol coverage | Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, TLS (ClientHello/ServerHello), HTTP (first-packet parsing). |
| No native reassembly | TCP/UDP stream tracking (conversation identity by 5-tuple) is supported natively, but native byte-level TCP stream reassembly or IP fragment reassembly is not implemented. The tshark backend provides TCP stream reassembly (`follow --payload`, `follow --http`) and TLS certificate extraction (`get_certificates`). These features require tshark to be installed. |
| Packet limit | The MCP server rejects captures with more than 100,000 packets. The CLI has no hard limit but memory scales linearly. |
| No GUI | CLI and MCP server only. No graphical interface. |

## Troubleshooting

### Unsupported Link Type

```
Error: unsupported link type
```

The capture file uses a link layer other than Ethernet (e.g., Wi-Fi, loopback, raw IP). Fireshark only supports Ethernet (link type 1). Convert the capture or use a tool that supports the link type.

### File Too Large / Out of Memory

Fireshark loads all packets into memory. For very large captures (hundreds of MB or GB), the process may exhaust available RAM. Solutions:

- Use `editcap` or `tcpdump` to extract a subset of the capture before analysis
- For MCP, the server rejects captures exceeding 100,000 packets with an explicit error

### Invalid Filter Expression

```
Error: parse error: unexpected token ...
```

The display filter expression has a syntax error. Check the filter language reference. Common mistakes:

- Missing `and`/`or` between clauses: `tcp port 443` should be `tcp and port 443`
- Using `=` instead of `==`: `ip.ttl = 64` should be `ip.ttl == 64`
- Unsupported field name: only fields listed in the filter reference are recognized

### Decode Warnings

```
warning: packet 42: truncated
```

Packets that are too short for their declared protocol are decoded as far as possible. A `DecodeIssue` is recorded but the packet still appears in output. This is normal for captures with snaplen limits or damaged traffic.

### Packet Not Found

```
Error: packet 999 not found (capture has fewer packets)
```

The requested packet number exceeds the number of packets in the capture. Packet numbers are 1-indexed.

### Invalid Capture File

```
Error: not a pcap/pcapng file
```

The file does not have a valid pcap or pcapng magic number. Ensure the file is not compressed (`.pcap.gz`) -- decompress it first.

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
