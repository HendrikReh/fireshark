use fireshark_core::{DecodedFrame, Frame};
use fireshark_dissectors::decode_packet;
use fireshark_filter::{compile, matches, unknown_field_names};

#[test]
fn compiled_filter_api_matches_decoded_frame() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();
    let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
    let decoded = DecodedFrame::new(frame, packet);

    let filter = compile("tcp and port 443").unwrap();

    assert!(matches(&filter, &decoded));
}

#[test]
fn invalid_regex_rejected_at_compile_time() {
    let result = compile(r#"dns.qname matches "[invalid""#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("invalid regex"),
        "error should mention regex: {err}"
    );
}

#[test]
fn unknown_field_names_detects_typos() {
    let filter = compile("tcp.srport == 80").unwrap();
    let unknown = unknown_field_names(&filter);
    assert_eq!(unknown, vec!["tcp.srport"]);
}

#[test]
fn known_fields_produce_no_warnings() {
    let filter = compile("tcp.srcport == 80 and ip.dst == 10.0.0.1").unwrap();
    let unknown = unknown_field_names(&filter);
    assert!(unknown.is_empty());
}
