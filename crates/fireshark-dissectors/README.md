# fireshark-dissectors

Protocol decoders for the fireshark packet analyzer.

## Overview

Decodes raw Ethernet frames into structured, typed protocol layers. Each dissector validates headers, extracts fields per RFC, validates checksums (IPv4 header, TCP, UDP), and reports decode issues (truncation, malformation, checksum mismatch) instead of panicking. Zero checksums (common with NIC offload) are skipped.

## Supported Protocols

| Protocol | Key Fields |
|----------|-----------|
| Ethernet | destination, source MACs, EtherType |
| ARP | operation, sender/target protocol addresses |
| IPv4 | addresses, TTL, ID, DSCP, ECN, DF/MF flags, fragment offset, checksum |
| IPv6 | addresses, next header, hop limit, traffic class, flow label |
| TCP | ports, seq, ack, flags (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), window, data offset |
| UDP | ports, length |
| ICMP | type, code, typed detail (echo request/reply, destination unreachable) |
| DNS | transaction ID, query/response, opcode, question count, answer count, query name, query type, A/AAAA answer records |
| TLS ClientHello | record version, client version, cipher suites, compression methods, SNI, ALPN, supported versions, signature algorithms, key share groups |
| TLS ServerHello | record version, server version, cipher suite, compression method, selected version, ALPN, key share group |

## Usage

```rust
use fireshark_dissectors::decode_packet;

let bytes: &[u8] = /* raw Ethernet frame */;
let packet = decode_packet(bytes)?;

for layer in packet.layers() {
    println!("{}", layer.name());
}
```

## Decode Pipeline

`decode_packet` chains dissectors: Ethernet -> (ARP | IPv4 | IPv6) -> (TCP | UDP | ICMP) -> (DNS | TLS). Application-layer protocols use two dispatch strategies: DNS is dispatched by port number (UDP port 53), while TLS uses heuristic dispatch on any TCP port by inspecting the TLS record header bytes (`0x16 0x03`). Each step:

1. Validates minimum header length
2. Extracts typed fields from network byte order
3. Returns the layer and a payload slice for the next dissector
4. Non-initial IPv4 fragments skip transport layer decoding

Layer byte spans are tracked alongside layers for hex dump coloring.

## Error Handling

- `DecodeError::Truncated` — buffer too short for the protocol header
- `DecodeError::Malformed` — header fields are invalid (wrong version, bad IHL, etc.)
- `DecodeIssueKind::ChecksumMismatch` — IPv4 header, TCP, or UDP checksum does not match computed value (zero checksums from NIC offload are skipped)

Decode errors at inner layers are captured as `DecodeIssue` on the packet, not propagated as `Err`. Only Ethernet truncation prevents packet creation entirely.

---

**Version:** 0.6.0 | **Last updated:** 2026-03-18 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
