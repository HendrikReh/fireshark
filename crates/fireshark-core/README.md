# fireshark-core

Core domain types for the fireshark packet analyzer.

## Overview

This crate defines the foundational types that all other fireshark crates depend on. It has zero external dependencies.

## Key Types

- **`Frame`** / **`FrameBuilder`** — raw captured frame with timestamp, captured length, original wire length, and raw bytes
- **`Packet`** — decoded packet containing layers, decode issues, and optional layer byte spans
- **`Layer`** — enum wrapping typed protocol layer structs (`EthernetLayer`, `Ipv4Layer`, `TcpLayer`, etc.)
- **`LayerSpan`** — byte offset and length marking where a layer lives in the raw frame data
- **`Pipeline`** / **`DecodedFrame`** — generic iterator that pairs frames with decoded packets
- **`TrackingPipeline`** — wraps `Pipeline`, assigns stream IDs via `StreamTracker` during iteration
- **`StreamKey`** — canonical 5-tuple (lower addr/port, higher addr/port, protocol) identifying a bidirectional conversation
- **`StreamMetadata`** — per-stream statistics: packet count, byte count, first/last seen timestamps
- **`StreamTracker`** — maps `StreamKey` values to monotonic `u32` stream IDs, accumulates per-stream metadata
- **`PacketSummary`** — one-line summary with protocol, endpoints, ports, timestamp, and length
- **`DecodeIssue`** — structured error with kind (truncated/malformed/checksum mismatch) and byte offset. `DecodeIssueKind::ChecksumMismatch` is produced when IPv4 header, TCP, or UDP checksums fail validation (zero checksums from NIC offload are skipped)

## Layer Types

Each protocol has a plain struct with public fields:

| Struct | Fields |
|--------|--------|
| `EthernetLayer` | destination, source, ether_type |
| `ArpLayer` | operation, sender/target protocol addresses |
| `Ipv4Layer` | source, destination, protocol, TTL, ID, DSCP, ECN, flags, checksum |
| `Ipv6Layer` | source, destination, next_header, traffic_class, flow_label, hop_limit |
| `TcpLayer` | ports, seq, ack, data_offset, flags (`TcpFlags`), window |
| `UdpLayer` | ports, length |
| `IcmpLayer` | type, code, detail (`IcmpDetail`) |
| `DnsLayer` | transaction_id, is_response, opcode, rcode, question_count, answer_count, query_name, query_type, answers |
| `DnsAnswer` | name, record_type, ttl, data (`DnsAnswerData`) |
| `DnsAnswerData` | A (IPv4), Aaaa (IPv6), Other (raw bytes) |
| `TlsClientHelloLayer` | record_version, client_version, cipher_suites, compression_methods, sni, alpn, supported_versions, signature_algorithms, key_share_groups |
| `TlsServerHelloLayer` | record_version, server_version, cipher_suite, compression_method, selected_version, alpn, key_share_group |
| `HttpLayer` | method, uri, host, status_code, content_type |

---

**Version:** 0.9.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
