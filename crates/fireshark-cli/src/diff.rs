//! Capture comparison (diff) command.

use std::path::Path;

use fireshark_backend::{BackendCapture, BackendKind, compare};

use crate::json::{DiffFileJson, DiffJson, HostDiffJson, PortDiffJson, ProtocolDiffJson};

pub fn run(
    path_a: &Path,
    path_b: &Path,
    backend: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let kind: BackendKind = backend
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    let a = BackendCapture::open(path_a, kind)?;
    let b = BackendCapture::open(path_b, kind)?;

    let result = compare(&a, &b);

    if json {
        let diff = DiffJson {
            file_a: DiffFileJson {
                path: path_a.display().to_string(),
                packet_count: result.a_packet_count,
                stream_count: result.a_stream_count,
            },
            file_b: DiffFileJson {
                path: path_b.display().to_string(),
                packet_count: result.b_packet_count,
                stream_count: result.b_stream_count,
            },
            new_hosts: result
                .new_hosts
                .iter()
                .map(|(host, count)| HostDiffJson {
                    host: host.clone(),
                    count: *count,
                })
                .collect(),
            missing_hosts: result
                .missing_hosts
                .iter()
                .map(|(host, count)| HostDiffJson {
                    host: host.clone(),
                    count: *count,
                })
                .collect(),
            new_protocols: result
                .new_protocols
                .iter()
                .map(|(name, count)| ProtocolDiffJson {
                    name: name.clone(),
                    count: *count,
                })
                .collect(),
            new_ports: result
                .new_ports
                .iter()
                .map(|(port, count)| PortDiffJson {
                    port: *port,
                    count: *count,
                })
                .collect(),
            missing_protocols: result
                .missing_protocols
                .iter()
                .map(|(name, count)| ProtocolDiffJson {
                    name: name.clone(),
                    count: *count,
                })
                .collect(),
            missing_ports: result
                .missing_ports
                .iter()
                .map(|(port, count)| PortDiffJson {
                    port: *port,
                    count: *count,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string(&diff).unwrap());
    } else {
        let file_a_name = path_a
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path_a.display().to_string());
        let file_b_name = path_b
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path_b.display().to_string());

        println!("Capture Comparison");
        println!("{}", "\u{2500}".repeat(38));
        println!(
            "  File A: {}  ({} packets, {} streams)",
            file_a_name, result.a_packet_count, result.a_stream_count
        );
        println!(
            "  File B: {}  ({} packets, {} streams)",
            file_b_name, result.b_packet_count, result.b_stream_count
        );
        println!();

        let packet_delta = result.b_packet_count as i64 - result.a_packet_count as i64;
        let stream_delta = result.b_stream_count as i64 - result.a_stream_count as i64;
        println!("  Packet delta:   {:+}", packet_delta);
        println!("  Stream delta:   {:+}", stream_delta);

        if !result.new_hosts.is_empty() {
            println!();
            println!("  New hosts in B (not in A):");
            for (host, count) in &result.new_hosts {
                println!("    {host:<16}{count} packets");
            }
        }

        if !result.missing_hosts.is_empty() {
            println!();
            println!("  Missing hosts from A (not in B):");
            for (host, count) in &result.missing_hosts {
                println!("    {host:<16}{count} packets");
            }
        }

        if !result.new_protocols.is_empty() {
            println!();
            println!("  New protocols in B:");
            for (name, count) in &result.new_protocols {
                println!("    {name:<16}{count} packets");
            }
        }

        if !result.missing_protocols.is_empty() {
            println!();
            println!("  Missing protocols from A (not in B):");
            for (name, count) in &result.missing_protocols {
                println!("    {name:<16}{count} packets");
            }
        }

        if !result.new_ports.is_empty() {
            println!();
            println!("  New ports in B:");
            for (port, count) in &result.new_ports {
                println!("    {port:<16}{count} packets");
            }
        }

        if !result.missing_ports.is_empty() {
            println!();
            println!("  Missing ports from A (not in B):");
            for (port, count) in &result.missing_ports {
                println!("    {port:<16}{count} packets");
            }
        }
    }

    Ok(())
}
