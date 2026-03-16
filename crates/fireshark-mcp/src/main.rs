use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if matches!(env::args().nth(1).as_deref(), Some("--help") | Some("-h")) {
        println!("fireshark-mcp\n\nUsage: fireshark-mcp");
        return Ok(());
    }

    fireshark_mcp::server::run_stdio().await
}
