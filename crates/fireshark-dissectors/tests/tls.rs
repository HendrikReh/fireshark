use fireshark_core::Layer;
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_tls_client_hello() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin");
    let packet = decode_packet(bytes).unwrap();

    let ch = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::TlsClientHello(l) => Some(l),
            _ => None,
        })
        .expect("TLS ClientHello layer");

    assert_eq!(ch.sni.as_deref(), Some("example.com"));
    assert_eq!(ch.cipher_suites.len(), 4);
    assert_eq!(ch.cipher_suites, vec![0x1301, 0x1302, 0x1303, 0xC02F]);
    assert_eq!(ch.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(ch.supported_versions, vec![0x0304, 0x0303]);
    assert_eq!(ch.signature_algorithms, vec![0x0403, 0x0804]);
    assert_eq!(ch.key_share_groups, vec![0x001D]);
    assert_eq!(ch.client_version, 0x0303);
    assert_eq!(ch.compression_methods, vec![0x00]);
}

#[test]
fn decodes_tls_server_hello() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_tls_server_hello.bin");
    let packet = decode_packet(bytes).unwrap();

    let sh = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::TlsServerHello(l) => Some(l),
            _ => None,
        })
        .expect("TLS ServerHello layer");

    assert_eq!(sh.cipher_suite, 0x1301);
    assert_eq!(sh.selected_version, Some(0x0304));
    assert_eq!(sh.key_share_group, Some(0x001D));
    assert_eq!(sh.server_version, 0x0303);
    assert_eq!(sh.compression_method, 0x00);
}

#[test]
fn tls_layer_names() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin");
    let packet = decode_packet(bytes).unwrap();

    let names: Vec<&str> = packet.layers().iter().map(|l| l.name()).collect();
    assert_eq!(names, vec!["Ethernet", "IPv4", "TCP", "TLS"]);
}

#[test]
fn tls_truncated_record() {
    // Build a TCP packet with a TLS-like payload that's too short (< 9 bytes of TLS)
    // Ethernet(14) + IPv4(20) + TCP(20) + TLS(4 bytes, truncated)
    let mut frame = Vec::new();

    // Ethernet header
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    let ip_total_len: u16 = 20 + 20 + 8; // 8 bytes of payload
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x40, 0x00]);
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[192, 0, 2, 10]);
    frame.extend_from_slice(&[198, 51, 100, 20]);

    // TCP header (20 bytes)
    frame.extend_from_slice(&49152u16.to_be_bytes()); // src port
    frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
    frame.extend_from_slice(&1000u32.to_be_bytes()); // seq
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.push(0x50); // data_offset=5
    frame.push(0x18); // PSH+ACK
    frame.extend_from_slice(&65535u16.to_be_bytes()); // window
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(&[0x00, 0x00]); // urgent

    // TLS-like payload, 8 bytes (heuristic passes but record < 9 bytes)
    frame.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00]);

    let packet = decode_packet(&frame).unwrap();

    // Should have Ethernet + IPv4 + TCP but TLS truncated -> issue
    assert!(packet.layer_names().contains(&"TCP"));
    assert!(!packet.layer_names().contains(&"TLS"));
    assert!(!packet.issues().is_empty());
}

#[test]
fn non_tls_tcp_not_dispatched() {
    // TCP packet with HTTP-like payload (starts with 'G' = 0x47)
    let mut frame = Vec::new();

    // Ethernet header
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header
    let ip_total_len: u16 = 20 + 20 + 10;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x40, 0x00]);
    frame.push(64);
    frame.push(6); // TCP
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[192, 0, 2, 10]);
    frame.extend_from_slice(&[198, 51, 100, 20]);

    // TCP header
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes()); // port 80
    frame.extend_from_slice(&1000u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push(0x50); // data_offset=5
    frame.push(0x18);
    frame.extend_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x00, 0x00]);

    // HTTP-like payload: "GET / HTTP"
    frame.extend_from_slice(b"GET / HTTP");

    let packet = decode_packet(&frame).unwrap();

    let names = packet.layer_names();
    assert!(names.contains(&"TCP"));
    assert!(!names.contains(&"TLS"));
    assert!(packet.issues().is_empty());
}
