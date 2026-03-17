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
- **`PacketSummary`** — one-line summary with protocol, endpoints, ports, timestamp, and length
- **`DecodeIssue`** — structured error with kind (truncated/malformed) and byte offset

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
| `DnsLayer` | transaction_id, is_response, opcode, question_count, answer_count, query_name, query_type, answers |
| `DnsAnswer` | name, record_type, ttl, data (`DnsAnswerData`) |
| `DnsAnswerData` | A (IPv4), Aaaa (IPv6), Other (raw bytes) |
| `TlsClientHelloLayer` | record_version, client_version, cipher_suites, compression_methods, sni, alpn, supported_versions, signature_algorithms, key_share_groups |
| `TlsServerHelloLayer` | record_version, server_version, cipher_suite, compression_method, selected_version, alpn, key_share_group |

---

**Version:** 0.4.0 | **Last updated:** 2026-03-17 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
