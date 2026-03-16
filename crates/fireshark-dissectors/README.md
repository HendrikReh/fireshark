# fireshark-dissectors

Protocol decoders for the fireshark packet analyzer.

## Overview

Decodes raw Ethernet frames into structured, typed protocol layers. Each dissector validates headers, extracts fields per RFC, and reports decode issues (truncation, malformation) instead of panicking.

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

`decode_packet` chains dissectors: Ethernet -> (ARP | IPv4 | IPv6) -> (TCP | UDP | ICMP). Each step:

1. Validates minimum header length
2. Extracts typed fields from network byte order
3. Returns the layer and a payload slice for the next dissector
4. Non-initial IPv4 fragments skip transport layer decoding

Layer byte spans are tracked alongside layers for hex dump coloring.

## Error Handling

- `DecodeError::Truncated` — buffer too short for the protocol header
- `DecodeError::Malformed` — header fields are invalid (wrong version, bad IHL, etc.)

Decode errors at inner layers are captured as `DecodeIssue` on the packet, not propagated as `Err`. Only Ethernet truncation prevents packet creation entirely.

---

**Version:** 0.2.2 | **Last updated:** 2026-03-16 | **Maintained by:** <hendrik.reh@blacksmith-consulting.ai>
