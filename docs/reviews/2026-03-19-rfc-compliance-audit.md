# RFC-Level Protocol Compliance Audit

Date: 2026-03-19

Issue: `fireshark-stf`

## Scope

Reviewed the native protocol decoding path in:

- `crates/fireshark-dissectors/src/ethernet.rs`
- `crates/fireshark-dissectors/src/arp.rs`
- `crates/fireshark-dissectors/src/ipv4.rs`
- `crates/fireshark-dissectors/src/ipv6.rs`
- `crates/fireshark-dissectors/src/tcp.rs`
- `crates/fireshark-dissectors/src/udp.rs`
- `crates/fireshark-dissectors/src/icmp.rs`
- `crates/fireshark-dissectors/src/dns.rs`
- `crates/fireshark-dissectors/src/tls.rs`
- `crates/fireshark-dissectors/src/http.rs`
- `crates/fireshark-dissectors/src/lib.rs`

Primary sources used:

- RFC 791
- RFC 768
- RFC 793
- RFC 8200
- RFC 1035
- RFC 7231
- RFC 4443
- RFC 8446

## Conformant Areas

- Ethernet, ARP, IPv4, TCP, UDP, and ICMP minimum-header truncation handling is straightforward and does not panic on short input.
- IPv4 parsing validates version, IHL, total length, and header checksum, and reports truncation when the capture is shorter than the declared IP packet length.
- UDP rejects impossible length values below the 8-byte header minimum.
- DNS and TLS now surface truncation as decode issues instead of silently accepting obviously incomplete payloads.
- TLS ClientHello and ServerHello parsing covers the common extension fields currently exposed by the data model.

## Confirmed Gaps

1. DNS compression pointers are not followed.
   `parse_name()` stops at a compression pointer and returns only the labels already accumulated, or an empty name for pointer-only names. RFC 1035 section 4.1.4 permits names to be represented as labels, pointers, or labels ending in a pointer. This is a real standards gap for common DNS responses.
   Tracked by `fireshark-j3u`.

2. Fragmented IPv4 TCP/UDP packets can be marked with false checksum mismatches.
   The orchestrator allows transport parsing whenever `fragment_offset == 0`, which includes the first fragment of a fragmented datagram, and then validates the transport checksum over the fragment bytes. RFC 768 and RFC 793 define the checksum over the full UDP datagram or TCP segment, so validating a partial first fragment is not sound.
   Tracked by `fireshark-3vu`.

3. IPv6 extension headers are not processed.
   The IPv6 dissector returns the base-header `next_header` directly, and transport dispatch only proceeds when that value is already TCP, UDP, or ICMP. RFC 8200 requires extension headers to be processed in order until the upper-layer header is reached. Packets with legitimate extension-header chains currently stop at the IPv6 layer.
   Tracked by `fireshark-mgc`.

4. IPv6 TCP/UDP checksums are not validated.
   The current checksum path is IPv4-only. RFC 8200 section 8.1 defines the IPv6 pseudo-header rules, and UDP checksums are mandatory for normal IPv6 traffic. This means corrupted IPv6 TCP/UDP payloads are not flagged today.
   Tracked by `fireshark-51a`.

5. HTTP TRACE requests are not recognized by the dispatch gate.
   The HTTP signature list omits `TRACE`, even though it is a standard request method. Valid TRACE traffic will therefore not be decoded as HTTP by the current heuristic gate.
   Tracked by `fireshark-1zl`.

## Residual Notes

- ICMPv6 parsing remains shallow relative to RFC 4443. The current audit did not file a separate issue because the higher-impact decode and validation gaps above were more urgent.
- I did not file issues for intentionally narrow current scope where the implementation is explicit and non-misleading, such as ARP support being limited to Ethernet/IPv4.

## Verification

Executed:

- `cargo test -p fireshark-dissectors -p fireshark-core`
- `cargo clippy -p fireshark-dissectors -p fireshark-core --all-targets --all-features -- -D warnings`
