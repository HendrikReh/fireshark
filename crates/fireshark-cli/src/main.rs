mod audit;
mod color;
mod detail;
mod diff;
mod follow;
mod hexdump;
mod issues;
mod json;
mod render;
mod stats;
mod summary;
mod timestamp;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "fireshark",
    about = "Packet analyzer built for LLMs and humans",
    long_about = "Rust-native protocol dissection with MCP server for LLM-driven security audits,\n\
                  Wireshark-style display filters, stream tracking, and an optional tshark backend."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List packets with color-coded protocol summary
    Summary {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Display filter expression (e.g., "tcp and port 443")
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
    },
    /// Inspect a single packet with decoded layer tree and hex dump
    Detail {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Packet number (1-indexed)
        packet: usize,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    /// Show capture statistics: packet count, streams, protocol distribution, top endpoints
    Stats {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
    },
    /// List decode issues (truncated or malformed packets)
    Issues {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
    },
    /// Run security audit heuristics on a capture file
    Audit {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Maximum number of packets to analyze (default: 100000)
        #[arg(long = "max-packets", default_value = "100000")]
        max_packets: usize,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
        /// Audit profile: security, dns, quality (default: all)
        #[arg(long = "profile")]
        profile: Option<String>,
    },
    /// Show all packets in a TCP/UDP conversation by stream ID
    Follow {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Stream ID (from stats or summary output)
        stream: u32,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend")]
        backend: Option<String>,
        /// Show reassembled payload (requires tshark backend)
        #[arg(long = "payload")]
        payload: bool,
        /// Show HTTP request/response (requires tshark backend)
        #[arg(long = "http")]
        http: bool,
    },
    /// Compare two capture files and show differences
    Diff {
        /// First capture file (baseline)
        path_a: PathBuf,
        /// Second capture file (to compare)
        path_b: PathBuf,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },
}

fn require_native_backend(
    backend: &str,
    command_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if backend != "native" {
        return Err(
            format!("backend '{backend}' does not support the '{command_name}' command").into(),
        );
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Summary {
            path,
            filter,
            backend,
            json,
        } => summary::run(&path, filter.as_deref(), &backend, json)?,
        Command::Detail {
            path,
            packet,
            backend,
        } => {
            require_native_backend(&backend, "detail")?;
            detail::run(&path, packet)?;
        }
        Command::Stats {
            path,
            backend,
            json,
        } => stats::run(&path, &backend, json)?,
        Command::Issues {
            path,
            backend,
            json,
        } => {
            require_native_backend(&backend, "issues")?;
            issues::run(&path, json)?;
        }
        Command::Audit {
            path,
            backend,
            max_packets,
            json,
            profile,
        } => {
            require_native_backend(&backend, "audit")?;
            audit::run(&path, max_packets, json, profile.as_deref())?;
        }
        Command::Follow {
            path,
            stream,
            backend,
            payload,
            http,
        } => {
            if payload || http {
                // --payload and --http imply tshark. Error only if user
                // explicitly chose native.
                if backend.as_deref() == Some("native") {
                    let flag = if payload { "--payload" } else { "--http" };
                    return Err(format!(
                        "{flag} requires the tshark backend; use --backend tshark or omit --backend"
                    )
                    .into());
                }
                follow::run_reassembly(&path, stream, payload, http)?;
            } else {
                let backend_str = backend.as_deref().unwrap_or("native");
                require_native_backend(backend_str, "follow")?;
                follow::run(&path, stream)?;
            }
        }
        Command::Diff {
            path_a,
            path_b,
            backend,
            json,
        } => diff::run(&path_a, &path_b, &backend, json)?,
    }

    Ok(())
}
