# RFC Compliance Audit Reference

This document captures the RFC-level protocol compliance audit that was completed on 2026-03-19 under `fireshark-stf` and serves as the canonical maintainer-facing report.

## Scope

Reviewed the native decoding path in:

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

## Primary Sources Used

- RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035>
- RFC 791: <https://www.rfc-editor.org/rfc/rfc791>
- RFC 768: <https://www.rfc-editor.org/rfc/rfc768>
- RFC 793: <https://www.rfc-editor.org/rfc/rfc793>
- RFC 8200: <https://www.rfc-editor.org/rfc/rfc8200>
- RFC 7231: <https://www.rfc-editor.org/rfc/rfc7231>
- RFC 4443: <https://www.rfc-editor.org/rfc/rfc4443>
- RFC 8446: <https://www.rfc-editor.org/rfc/rfc8446>

## Conformant Areas

- Ethernet, ARP, IPv4, TCP, UDP, and ICMP minimum-header truncation handling does not panic on short input.
- IPv4 parsing validates version, IHL, total length, and header checksum, and reports truncation when the capture is shorter than the declared IP packet length.
- UDP rejects impossible length values below the 8-byte header minimum.
- DNS and TLS surface truncation as decode issues instead of silently accepting obviously incomplete payloads.
- TLS ClientHello and ServerHello parsing covers the common extension fields currently exposed by the data model.

## Audit Findings

The audit identified the following substantive protocol-compliance gaps:

1. DNS compression pointers were not followed.
2. Fragmented IPv4 TCP/UDP packets could produce false checksum mismatches.
3. IPv6 extension headers were not processed before transport dispatch.
4. IPv6 TCP/UDP checksums were not validated.
5. HTTP TRACE requests were not recognized by the HTTP dispatch gate.
6. IPv6 atomic fragments bypassed transport checksum validation.

## Outcome

All audit findings above were fixed and tracked through child issues of `fireshark-stf`:

- `fireshark-j3u` DNS compression pointers
- `fireshark-3vu` fragmented IPv4 transport checksum handling
- `fireshark-mgc` IPv6 extension-header processing
- `fireshark-51a` IPv6 TCP/UDP checksum validation
- `fireshark-1zl` HTTP TRACE recognition
- `fireshark-wju` IPv6 atomic fragment checksum validation

`fireshark-stf` is closed.

## Residual Notes

- ICMPv6 parsing remains intentionally shallow relative to RFC 4443; the audit did not treat that as a misleading standards bug in the current product scope.
- Narrow, explicit scope limits such as ARP support being focused on Ethernet/IPv4 were not filed as compliance bugs when the implementation was clear about that scope.
