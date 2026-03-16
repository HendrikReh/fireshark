mod support;

use assert_cmd::cargo::cargo_bin;
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::TokioChildProcess,
};
use tokio::process::Command;

#[tokio::test]
async fn stdio_server_handles_open_capture_tool() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let transport = TokioChildProcess::new(Command::new(cargo_bin("fireshark-mcp"))).unwrap();
    let client = ().serve(transport).await.unwrap();

    let result = client
        .call_tool(CallToolRequestParams {
            meta: None,
            name: "open_capture".into(),
            arguments: Some(
                serde_json::json!({
                    "path": fixture.to_string_lossy(),
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            task: None,
        })
        .await
        .unwrap();

    let structured = result.structured_content.unwrap();

    assert!(structured
        .get("session_id")
        .and_then(|value| value.as_str())
        .is_some());

    client.cancel().await.unwrap();
}
