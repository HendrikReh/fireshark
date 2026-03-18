use fireshark_core::{DecodedFrame, Frame};
use fireshark_dissectors::decode_packet;
use fireshark_filter::{compile, matches};

#[test]
fn compiled_filter_api_matches_decoded_frame() {
    let bytes = include_bytes!("../../../fixtures/bytes/ethernet_ipv4_tcp.bin");
    let packet = decode_packet(bytes).unwrap();
    let frame = Frame::builder().data(bytes.to_vec()).build().unwrap();
    let decoded = DecodedFrame::new(frame, packet);

    let filter = compile("tcp and port 443").unwrap();

    assert!(matches(&filter, &decoded));
}
