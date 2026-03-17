# Audit Heuristics v2 — Design Spec

## Purpose

Add two new audit heuristics to fireshark-mcp: cleartext credential exposure detection and DNS tunneling detection. Both are port/field-based heuristics following the existing audit pattern — no payload inspection.

## Heuristic 1: Cleartext Credential Exposure

Flags traffic to ports associated with cleartext authentication protocols.

### Ports

| Port | Protocol | Risk |
|------|----------|------|
| 21 | FTP | Commands and passwords sent in cleartext |
| 23 | Telnet | Full session in cleartext |
| 80 | HTTP | Basic auth headers in cleartext |
| 110 | POP3 | USER/PASS in cleartext |
| 143 | IMAP | LOGIN in cleartext |

### Finding shape

- `id`: `"cleartext-{protocol}"` (e.g., `"cleartext-ftp"`)
- `severity`: `"high"`
- `category`: `"cleartext_credentials"`
- `title`: `"{protocol} traffic on port {port} may expose credentials in cleartext"`
- `summary`: explains the risk for the specific protocol
- `evidence`: packet indexes of matching traffic, capped at `MAX_EVIDENCE_PACKETS`

One finding per cleartext port observed (same pattern as `audit_suspicious_ports`).

Note: port 23 overlaps with `SUSPICIOUS_PORTS`. Intentional — different analytical lens (suspicious service vs credential exposure).

### Implementation

New function `audit_cleartext_credentials(capture) -> Vec<FindingView>` in `audit.rs`. Iterates packets, checks destination port against the cleartext port list. Uses the existing `MAX_EVIDENCE_PACKETS` cap.

## Heuristic 2: DNS Tunneling Detection

Flags sources exhibiting DNS tunneling indicators.

### Indicators

| Indicator | Threshold | Why |
|-----------|-----------|-----|
| Long query labels | > 50 chars in any label | Tunneled data encoded in subdomains |
| High unique query count | > 50 unique names from one source | Rapid unique queries suggest automation |
| TXT record queries | > 10 TXT queries from one source | TXT commonly used for data exfiltration |

### Finding shape

- `id`: `"dns-tunneling-{source_ip}"`
- `severity`: `"high"`
- `category`: `"dns_tunneling"`
- `title`: `"Possible DNS tunneling from {source_ip}"`
- `summary`: describes which indicators were triggered
- `evidence`: packet indexes of suspicious DNS queries, capped at `MAX_EVIDENCE_PACKETS`

One finding per suspicious source IP.

### Implementation

New function `audit_dns_tunneling(capture) -> Vec<FindingView>` in `audit.rs`. Iterates packets, finds `Layer::Dns` with `query_name`, tracks per-source metrics. Uses `source_host()` helper (already exists). Checks if any indicator exceeds its threshold.

A query name has "long labels" if any segment between dots exceeds 50 characters.

## Changes

- Modify: `crates/fireshark-mcp/src/audit.rs` — add two functions, wire into `AuditEngine::audit`
- Modify: `crates/fireshark-mcp/tests/audit.rs` — add tests for each heuristic

No changes to other crates.

## Testing

- `audit_flags_cleartext_ftp` — synthetic packets with dst port 21, verify finding
- `audit_flags_cleartext_telnet` — dst port 23, verify finding
- `audit_does_not_flag_cleartext_for_encrypted_ports` — dst port 443, no finding
- `audit_flags_dns_tunneling_long_labels` — DNS queries with 60-char labels
- `audit_flags_dns_tunneling_high_unique_count` — 60 unique DNS query names from one source
- `audit_does_not_flag_normal_dns` — small number of short DNS queries, no finding

## Out of Scope

- Payload inspection (actual credential detection in packet content)
- DNS over HTTPS/TLS detection
- Whitelisting or suppression of known-safe patterns
