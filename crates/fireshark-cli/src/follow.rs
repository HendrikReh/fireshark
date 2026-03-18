//! Follow a single stream by ID, showing its header and all matching packets.

use std::path::Path;

use fireshark_backend::reassembly::{Direction, FollowMode};
use fireshark_core::TrackingPipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;

pub fn run(path: &Path, stream_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    // Collect all decoded frames, skipping errors with a warning.
    let mut frames = Vec::new();
    let mut packet_index: usize = 0;
    for result in pipeline.by_ref() {
        packet_index += 1;
        match result {
            Ok(decoded) => {
                if decoded.stream_id() == Some(stream_id) {
                    frames.push((packet_index, decoded));
                }
            }
            Err(e) => {
                eprintln!("warning: packet {packet_index}: {e}");
            }
        }
    }

    let tracker = pipeline.into_tracker();

    let meta = match tracker.get(stream_id) {
        Some(meta) => meta,
        None => {
            return Err(format!(
                "stream {stream_id} not found (capture has {} streams)",
                tracker.stream_count()
            )
            .into());
        }
    };

    // Print stream header.
    let key = &meta.key;
    println!(
        "Stream {}: {} {}:{} \u{2194} {}:{}",
        stream_id,
        key.protocol_name(),
        key.addr_lo,
        key.port_lo,
        key.addr_hi,
        key.port_hi,
    );

    let duration = match (meta.first_seen, meta.last_seen) {
        (Some(first), Some(last)) => {
            let dur = last.saturating_sub(first);
            format!("{:.3}s", dur.as_secs_f64())
        }
        _ => String::from("-"),
    };

    println!(
        "{} packets, {} bytes, duration {}",
        meta.packet_count, meta.byte_count, duration,
    );
    println!("{}", "\u{2500}".repeat(38));

    // Print packets belonging to this stream.
    for (index, decoded) in &frames {
        let summary = decoded.summary();
        let line = crate::summary::format_line(
            *index,
            summary.timestamp,
            &summary.protocol,
            &summary.source,
            &summary.destination,
            summary.length,
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}

/// Reassemble and display stream payload via the tshark backend.
///
/// When `payload` is true, shows a hex dump of the reassembled TCP stream.
/// When `http` is true, shows the HTTP request/response exchange.
pub fn run_reassembly(
    path: &Path,
    stream_id: u32,
    payload: bool,
    http: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tshark_path, _version) =
        fireshark_tshark::discover().map_err(|e| format!("tshark required for reassembly: {e}"))?;

    if payload {
        let stream_payload = fireshark_tshark::follow::follow_stream(
            &tshark_path,
            path,
            stream_id,
            FollowMode::Tcp,
        )?;

        println!(
            "Stream {}: {} <-> {}",
            stream_payload.stream_id, stream_payload.client, stream_payload.server
        );
        println!("{}", "\u{2500}".repeat(38));

        if stream_payload.segments.is_empty() {
            println!("(no payload data)");
        }
        for segment in &stream_payload.segments {
            let dir_label = match segment.direction {
                Direction::ClientToServer => ">>>",
                Direction::ServerToClient => "<<<",
            };
            println!("{dir_label} {} bytes", segment.data.len());
            print_hex_dump(&segment.data);
        }
    }

    if http {
        let stream_payload = fireshark_tshark::follow::follow_stream(
            &tshark_path,
            path,
            stream_id,
            FollowMode::Http,
        )?;

        println!(
            "Stream {}: {} <-> {}",
            stream_payload.stream_id, stream_payload.client, stream_payload.server
        );
        println!("{}", "\u{2500}".repeat(38));

        if stream_payload.segments.is_empty() {
            println!("(no HTTP data)");
        }
        for segment in &stream_payload.segments {
            let dir_label = match segment.direction {
                Direction::ClientToServer => ">>>",
                Direction::ServerToClient => "<<<",
            };
            let text = String::from_utf8_lossy(&segment.data);
            print!("{dir_label} {text}");
        }
    }

    Ok(())
}

/// Print a hex dump of the given bytes, 16 bytes per line.
fn print_hex_dump(data: &[u8]) {
    for (offset, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {:04x}  {:<48}  {}", offset * 16, hex.join(" "), ascii);
    }
}
