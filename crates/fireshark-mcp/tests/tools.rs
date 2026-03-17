mod support;

use fireshark_mcp::tools::ToolService;

#[tokio::test]
async fn open_capture_tool_returns_session_metadata() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();

    let result = service.open_capture(&fixture).await.unwrap();

    assert_eq!(result.packet_count, 1);
    assert!(!result.session_id.is_empty());
}

#[tokio::test]
async fn list_packets_tool_returns_capture_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let capture = service.open_capture(&fixture).await.unwrap();

    let packets = service
        .list_packets(&capture.session_id, 0, 10, None, None, None)
        .await
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
    assert!(packets[0].timestamp.is_some());
    assert!(packets[0].original_len > 0);
}
