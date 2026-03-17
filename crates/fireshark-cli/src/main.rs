mod audit;
mod color;
mod detail;
mod follow;
mod hexdump;
mod issues;
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
    },
    /// List decode issues (truncated or malformed packets)
    Issues {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
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
    },
    /// Show all packets in a TCP/UDP conversation by stream ID
    Follow {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Stream ID (from stats or summary output)
        stream: u32,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
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
        } => summary::run(&path, filter.as_deref(), &backend)?,
        Command::Detail {
            path,
            packet,
            backend,
        } => {
            require_native_backend(&backend, "detail")?;
            detail::run(&path, packet)?;
        }
        Command::Stats { path, backend } => stats::run(&path, &backend)?,
        Command::Issues { path, backend } => {
            require_native_backend(&backend, "issues")?;
            issues::run(&path)?;
        }
        Command::Audit {
            path,
            backend,
            max_packets,
        } => {
            require_native_backend(&backend, "audit")?;
            audit::run(&path, max_packets)?;
        }
        Command::Follow {
            path,
            stream,
            backend,
        } => {
            require_native_backend(&backend, "follow")?;
            follow::run(&path, stream)?;
        }
    }

    Ok(())
}
