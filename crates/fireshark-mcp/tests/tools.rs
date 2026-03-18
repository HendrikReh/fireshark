mod support;

use fireshark_mcp::tools::ToolService;

#[tokio::test]
async fn open_capture_tool_returns_session_metadata() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();

    let result = service.open_capture(&fixture, None).await.unwrap();

    assert_eq!(result.packet_count, 1);
    assert!(!result.session_id.is_empty());
}

#[tokio::test]
async fn list_packets_tool_returns_capture_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let capture = service.open_capture(&fixture, None).await.unwrap();

    let packets = service
        .list_packets(&capture.session_id, 0, 10, None, None, None)
        .await
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].protocol, "TCP");
    assert!(packets[0].timestamp.is_some());
    assert!(packets[0].original_len > 0);
}

#[tokio::test]
async fn list_streams_tool_returns_streams() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let response = service.open_capture(&fixture, None).await.unwrap();

    let streams = service
        .list_streams(&response.session_id, 0, 100)
        .await
        .unwrap();

    assert!(!streams.is_empty());
    assert_eq!(streams[0].id, 0);
    assert!(!streams[0].protocol.is_empty());
}

#[tokio::test]
async fn get_stream_tool_returns_stream_packets() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let response = service.open_capture(&fixture, None).await.unwrap();

    let (stream, packets) = service.get_stream(&response.session_id, 0).await.unwrap();

    assert_eq!(stream.id, 0);
    assert!(!packets.is_empty());
}

#[tokio::test]
async fn get_stream_tool_returns_error_for_invalid_id() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let response = service.open_capture(&fixture, None).await.unwrap();

    let result = service.get_stream(&response.session_id, 99999).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn summarize_capture_tool_returns_combined_summary() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();
    let response = service.open_capture(&fixture, None).await.unwrap();

    let summary = service
        .summarize_capture(&response.session_id)
        .await
        .unwrap();

    assert!(summary.packet_count > 0);
    assert!(summary.stream_count > 0);
    assert!(!summary.protocols.is_empty());
}

#[tokio::test]
async fn compare_captures_identical_returns_no_differences() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let service = ToolService::new_default();

    let resp_a = service.open_capture(&fixture, None).await.unwrap();
    let resp_b = service.open_capture(&fixture, None).await.unwrap();

    let comparison = service
        .compare_captures(&resp_a.session_id, &resp_b.session_id)
        .await
        .unwrap();

    assert_eq!(comparison.a_packet_count, comparison.b_packet_count);
    assert!(comparison.new_hosts.is_empty());
    assert!(comparison.missing_hosts.is_empty());
    assert!(comparison.new_protocols.is_empty());
    assert!(comparison.new_ports.is_empty());
}

#[tokio::test]
async fn compare_captures_returns_differences() {
    let fixture_a = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let fixture_b = support::repo_root().join("fixtures/smoke/fuzz-2006-06-26-2594.pcap");
    let service = ToolService::new_default();

    let resp_a = service.open_capture(&fixture_a, None).await.unwrap();
    let resp_b = service.open_capture(&fixture_b, None).await.unwrap();

    let comparison = service
        .compare_captures(&resp_a.session_id, &resp_b.session_id)
        .await
        .unwrap();

    // The two captures are different, so we should see different packet counts
    assert_ne!(comparison.a_packet_count, comparison.b_packet_count);
}
