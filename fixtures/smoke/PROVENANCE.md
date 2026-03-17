# Fixture Provenance

## wireshark-dns.pcap

- **Source:** https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures (dns.cap)
- **Original size:** 38 packets, 4.3 KB
- **Trimmed to:** 8 packets (first 4 query-response pairs)
- **Why added:** Real-world DNS with TXT (google.com), MX responses, and name compression. Validates DNS dissector against production traffic patterns our hand-crafted fixtures cannot replicate.

## wireshark-ipv4frags.pcap

- **Source:** https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures (ipv4frags.pcap)
- **Original size:** 3 packets, 3.0 KB
- **Why added:** Real IPv4 fragmentation: ICMP echo request (1400 bytes) split into first fragment (MF=1, offset=0) and continuation (offset=122). Tests fragment flag parsing and transport-layer skip on non-initial fragments with real-world packet structure.

## fuzz-2006-06-26-2594.pcap

- **Source:** Included from project inception
- **Why kept:** Fuzzing regression — 691 packets of mixed traffic (UDP, ARP, DNS, Unknown) exercising the full pipeline with potentially adversarial content.

## minimal.pcap / minimal.pcapng

- **Source:** Hand-crafted for the project
- **Why kept:** Minimal single-packet captures for fast CLI integration tests. Both pcap and pcapng formats covered.
