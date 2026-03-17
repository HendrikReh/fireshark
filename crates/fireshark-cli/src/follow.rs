//! Follow a single stream by ID, showing its header and all matching packets.

use std::path::Path;

use fireshark_core::TrackingPipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

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
        let ts = match summary.timestamp {
            Some(d) => timestamp::format_utc(d),
            None => String::from("-"),
        };
        let line = format!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            index, ts, summary.protocol, summary.source, summary.destination, summary.length,
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}
