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

## Ignored

None.

All open review comments on PR `#1` were technically valid for the current codebase and were implemented.
