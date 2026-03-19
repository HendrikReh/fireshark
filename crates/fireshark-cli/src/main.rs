mod audit;
mod certificates;
mod color;
mod detail;
mod diff;
mod follow;
mod hexdump;
mod issues;
mod json;
mod render;
mod search;
mod stats;
mod summary;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fireshark_backend::BackendKind;

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
    /// Search packets by protocol, address, port, or text
    Search {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Filter by protocol name (case-insensitive substring)
        #[arg(long)]
        protocol: Option<String>,
        /// Filter by source address (case-insensitive substring)
        #[arg(long)]
        source: Option<String>,
        /// Filter by destination address (case-insensitive substring)
        #[arg(long)]
        destination: Option<String>,
        /// Filter by port number (source or destination)
        #[arg(long)]
        port: Option<u16>,
        /// Filter by text (searches protocol, addresses, layer names)
        #[arg(long)]
        text: Option<String>,
        /// Show only packets with decode issues
        #[arg(long)]
        has_issues: bool,
        /// Display filter expression (combined with search criteria)
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
        /// Analysis backend: native (default) or tshark
        #[arg(long = "backend", default_value = "native")]
        backend: String,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
    },
    /// Extract TLS certificates from a capture file (requires tshark)
    Certificates {
        /// Path to a pcap or pcapng capture file
        path: PathBuf,
        /// Output as JSONL (one JSON object per line)
        #[arg(long = "json")]
        json: bool,
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

/// Parse a backend string into a [`BackendKind`], rejecting unknown values.
fn parse_backend(backend: &str) -> Result<BackendKind, Box<dyn std::error::Error>> {
    backend
        .parse::<BackendKind>()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

/// Parse and validate that the backend is native, rejecting both unknown
/// values and the tshark backend for native-only commands.
fn require_native(backend: &str, command_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let kind = parse_backend(backend)?;
    if kind != BackendKind::Native {
        return Err(format!("the '{command_name}' command requires the native backend").into());
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
            require_native(&backend, "detail")?;
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
            require_native(&backend, "issues")?;
            issues::run(&path, json)?;
        }
        Command::Audit {
            path,
            backend,
            max_packets,
            json,
            profile,
        } => {
            require_native(&backend, "audit")?;
            audit::run(&path, max_packets, json, profile.as_deref())?;
        }
        Command::Follow {
            path,
            stream,
            backend,
            payload,
            http,
        } => {
            // Validate the backend string up front (reject unknown values).
            let kind = match backend.as_deref() {
                Some(b) => Some(parse_backend(b)?),
                None => None,
            };

            if payload || http {
                // --payload and --http imply tshark. Error only if user
                // explicitly chose native.
                if kind == Some(BackendKind::Native) {
                    let flag = if payload { "--payload" } else { "--http" };
                    return Err(format!(
                        "{flag} requires the tshark backend; use --backend tshark or omit --backend"
                    )
                    .into());
                }
                follow::run_reassembly(&path, stream, payload, http)?;
            } else {
                if kind.is_some() && kind != Some(BackendKind::Native) {
                    return Err("the 'follow' command requires the native backend".into());
                }
                follow::run(&path, stream)?;
            }
        }
        Command::Search {
            path,
            protocol,
            source,
            destination,
            port,
            text,
            has_issues,
            filter,
            backend,
            json,
        } => {
            require_native(&backend, "search")?;
            let criteria = search::SearchCriteria {
                protocol: protocol.as_deref(),
                source: source.as_deref(),
                destination: destination.as_deref(),
                port,
                text: text.as_deref(),
                has_issues,
                filter: filter.as_deref(),
            };
            search::run(&path, &criteria, json)?;
        }
        Command::Certificates { path, json } => {
            certificates::run(&path, json)?;
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
