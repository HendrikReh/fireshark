//! Decode issue listing with colored severity.

use std::path::Path;

use colored::Colorize;
use fireshark_core::{DecodeIssueKind, Pipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::json::IssueJson;

pub fn run(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;

    let mut frame_index: usize = 0;
    let mut decoded_packet_count: usize = 0;
    let mut issues: Vec<(usize, String, usize)> = Vec::new();

    for result in Pipeline::new(reader, decode_packet) {
        frame_index += 1;
        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {frame_index}: {e}");
                continue;
            }
        };

        decoded_packet_count += 1;

        for issue in decoded.packet().issues() {
            let kind = match issue.kind() {
                DecodeIssueKind::Truncated => "Truncated",
                DecodeIssueKind::Malformed => "Malformed",
                DecodeIssueKind::ChecksumMismatch => "Checksum mismatch",
            };
            issues.push((frame_index, kind.to_string(), issue.offset()));
        }
    }

    if json {
        for (packet_num, kind, offset) in &issues {
            let issue = IssueJson {
                packet_index: *packet_num,
                kind: kind.clone(),
                offset: *offset,
            };
            println!("{}", serde_json::to_string(&issue).unwrap());
        }
    } else {
        println!("Decode Issues");
        println!("{}", "\u{2500}".repeat(38));

        for (packet_num, kind, offset) in &issues {
            let kind_colored = match kind.as_str() {
                "Malformed" => kind.red().to_string(),
                "Truncated" => kind.yellow().to_string(),
                "Checksum mismatch" => kind.yellow().to_string(),
                _ => kind.to_string(),
            };
            println!("  Packet {packet_num:<5} {kind_colored:<10} at offset {offset}");
        }

        println!();
        println!("{} issues in {decoded_packet_count} packets", issues.len());
    }

    Ok(())
}
