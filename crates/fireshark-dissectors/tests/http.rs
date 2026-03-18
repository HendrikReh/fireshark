use fireshark_core::Layer;
use fireshark_dissectors::decode_packet;

#[test]
fn decodes_http_get_from_fixture() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin");
    let packet = decode_packet(bytes).unwrap();

    let http = packet
        .layers()
        .iter()
        .find_map(|layer| match layer {
            Layer::Http(l) => Some(l),
            _ => None,
        })
        .expect("HTTP layer");

    assert!(http.is_request);
    assert_eq!(http.method.as_deref(), Some("GET"));
    assert_eq!(http.uri.as_deref(), Some("/"));
    assert_eq!(http.version, "HTTP/1.1");
    assert_eq!(http.host.as_deref(), Some("example.com"));
    assert_eq!(http.content_type.as_deref(), Some("text/html"));
}

#[test]
fn http_layer_names() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_http_get.bin");
    let packet = decode_packet(bytes).unwrap();

    let names: Vec<&str> = packet.layers().iter().map(|l| l.name()).collect();
    assert_eq!(names, vec!["Ethernet", "IPv4", "TCP", "HTTP"]);
}

#[test]
fn tls_not_dispatched_as_http() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin");
    let packet = decode_packet(bytes).unwrap();

    let has_http = packet
        .layers()
        .iter()
        .any(|layer| matches!(layer, Layer::Http(_)));
    assert!(
        !has_http,
        "TLS ClientHello should not be dispatched as HTTP"
    );
}

#[test]
fn non_http_tcp_not_dispatched() {
    // TCP packet with random (non-HTTP, non-TLS) payload
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
    frame.extend_from_slice(&8080u16.to_be_bytes());
    frame.extend_from_slice(&1000u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push(0x50); // data_offset=5
    frame.push(0x18);
    frame.extend_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x00, 0x00]);

    // Random non-HTTP, non-TLS payload
    frame.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);

    let packet = decode_packet(&frame).unwrap();

    let has_http = packet
        .layers()
        .iter()
        .any(|layer| matches!(layer, Layer::Http(_)));
    assert!(
        !has_http,
        "Random TCP payload should not be dispatched as HTTP"
    );
}
