# PR #1 Review Follow-Up

**PR:** `#1 Build Fireshark crawl phase`

## Fixed

1. `crates/fireshark-dissectors/src/ipv4.rs`
   Bound the IPv4 payload slice to the declared Total Length field and record a truncation issue when the capture ends before that declared length.

2. `crates/fireshark-dissectors/src/ipv6.rs`
   Bound the IPv6 payload slice to the declared Payload Length field and record a truncation issue when the capture ends before that declared length.

3. `crates/fireshark-dissectors/src/lib.rs`
   Stopped transport-layer parsing when the bounded network payload is empty so Ethernet padding does not produce fake TCP/UDP/ICMP truncation issues.

4. `crates/fireshark-dissectors/tests/transport.rs`
   Added regression tests for:
   - IPv4 padding being ignored
   - IPv4 declared-length truncation being reported
   - IPv6 padding being ignored
   - IPv6 declared-length truncation being reported

5. `crates/fireshark-dissectors/src/lib.rs`, `src/tcp.rs`, `src/udp.rs`, `src/icmp.rs`
   Threaded the real transport payload start offset through the IPv4/IPv6 decode path so TCP, UDP, and ICMP truncation issues report offsets relative to the actual transport header start instead of using a hardcoded Ethernet-only base.

6. `crates/fireshark-dissectors/tests/transport.rs`
   Added regression tests for:
   - TCP truncation offsets after IPv4 headers
   - UDP truncation offsets after IPv4 headers
   - ICMP truncation offsets after IPv6 headers

7. `crates/fireshark-file/src/reader.rs`, `src/error.rs`
   Reject unsupported link-layer types up front so `CaptureReader` no longer accepts non-Ethernet `pcap` or `pcapng` files that the decode pipeline would misinterpret as Ethernet traffic.

8. `crates/fireshark-file/tests/reject_unsupported_linktypes.rs`
   Added regression tests proving `CaptureReader::open` rejects `DataLink::RAW` captures for both `pcap` and `pcapng`.

9. `crates/fireshark-core/src/issues.rs`, `crates/fireshark-dissectors/src/lib.rs`
   Added a malformed decode-issue kind and now surface malformed layer parses as packet issues instead of silently dropping them from the decode result.

10. `crates/fireshark-core/src/layer.rs`, `crates/fireshark-dissectors/src/ipv4.rs`, `src/lib.rs`
    Exposed IPv4 fragment metadata on the decoded layer and skip transport parsing for non-initial IPv4 fragments so later fragments do not fabricate TCP/UDP/ICMP headers from fragment payload bytes.

11. `crates/fireshark-dissectors/tests/transport.rs`
    Added regression tests proving malformed IPv4 headers create decode issues and non-initial IPv4 fragments do not produce transport layers.

## Ignored

None.

All open review comments on PR `#1` were technically valid for the current codebase and were implemented.
