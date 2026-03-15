# Fixture Inventory

This directory contains the small binary fixtures used to drive the `crawl` phase.

## `smoke/`

- `minimal.pcap`
  One Ethernet/IPv4/TCP frame wrapped in legacy pcap format. Used for file-reader and pipeline smoke tests.
- `minimal.pcapng`
  The same Ethernet/IPv4/TCP frame wrapped in pcapng format. Used to verify pcapng ingestion.

## `bytes/`

- `ethernet_ipv4_tcp.bin`
  Ethernet + IPv4 + TCP header bytes for the baseline transport decode tests.
- `ethernet_ipv4_udp.bin`
  Ethernet + IPv4 + UDP header bytes for UDP port extraction tests.
- `ethernet_arp.bin`
  Ethernet + ARP request bytes for ARP layer detection tests.
- `ethernet_ipv6_icmp.bin`
  Ethernet + IPv6 + ICMPv6 echo-request bytes for IPv6 and ICMP layer detection tests.

## Origin

All fixtures in this phase are handcrafted byte sequences chosen to keep tests deterministic and easy to reason about. They are not intended to cover malformed captures or advanced protocol behavior yet.
