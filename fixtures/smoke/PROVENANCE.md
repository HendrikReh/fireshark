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

## ppa-dns-query-response.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition exercise captures
- **Original file:** ppa3ecaptures/dns_query_response.pcapng
- **Size:** 2 packets, 280 bytes
- **Why added:** Real DNS query/response pair — tests DNS dissector against production traffic with name compression

## ppa-tcp-handshake.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/tcp_handshake.pcapng
- **Size:** 3 packets, 336 bytes
- **Why added:** Complete TCP 3-way handshake — validates stream tracking and connection anomaly audit does NOT flag normal connections

## ppa-synscan.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/synscan.pcapng
- **Trimmed to:** First 100 packets (from 2011)
- **Why added:** Real SYN scan — tests scan detection audit heuristic against actual attack traffic

## ppa-arppoison.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/arppoison.pcapng
- **Size:** 165 packets, 66K
- **Why added:** ARP poisoning attack — tests ARP parsing and endpoint extraction under adversarial conditions

## ppa-icmp-traceroute.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/icmp_traceroute.pcapng
- **Size:** 54 packets, 6.9K
- **Why added:** Traceroute with TTL-exceeded ICMP — tests varied ICMP types beyond echo

## ppa-tcp-retransmissions.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/tcp_retransmissions.pcapng
- **Size:** 6 packets, 4.4K
- **Why added:** TCP retransmissions — tests stream tracking stability with duplicate sequence numbers

## ppa-cryptowall4-c2.pcapng
- **Source:** Practical Packet Analysis, 3rd Edition
- **Original file:** ppa3ecaptures/cryptowall4_c2.pcapng
- **Size:** 162 packets, 137K
- **Why added:** Malware C2 traffic — comprehensive integration test for audit heuristics (suspicious ports, connection patterns)
