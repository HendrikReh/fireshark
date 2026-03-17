//! Capture statistics: packet count, duration, protocol distribution, top endpoints.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::timestamp;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;

    let mut packet_count: usize = 0;
    let mut first_ts: Option<Duration> = None;
    let mut last_ts: Option<Duration> = None;
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoint_counts: BTreeMap<String, usize> = BTreeMap::new();

    for result in Pipeline::new(reader, decode_packet) {
        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", packet_count + 1);
                packet_count += 1;
                continue;
            }
        };

        packet_count += 1;

        if let Some(ts) = decoded.frame().timestamp() {
            if first_ts.is_none() || Some(ts) < first_ts {
                first_ts = Some(ts);
            }
            if last_ts.is_none() || Some(ts) > last_ts {
                last_ts = Some(ts);
            }
        }

        let summary = decoded.summary();
        *protocol_counts.entry(summary.protocol).or_insert(0) += 1;

        for endpoint in [summary.source, summary.destination] {
            if endpoint.is_empty() {
                continue;
            }
            *endpoint_counts.entry(endpoint).or_insert(0) += 1;
        }
    }

    println!("Capture Statistics");
    println!("{}", "\u{2500}".repeat(38));

    println!("Packets:    {packet_count}");

    match (first_ts, last_ts) {
        (Some(first), Some(last)) => {
            let duration = last.saturating_sub(first);
            println!(
                "Duration:   {} ({} \u{2192} {})",
                format_duration(duration),
                timestamp::format_utc(first),
                timestamp::format_utc(last)
            );
        }
        _ => {
            println!("Duration:   -");
        }
    }

    println!();
    println!("Protocol Distribution:");

    let mut protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
    protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (protocol, count) in &protocols {
        let pct = if packet_count > 0 {
            (*count as f64 / packet_count as f64) * 100.0
        } else {
            0.0
        };
        println!("  {protocol:<10} {count:>4}  ({pct:>4.1}%)");
    }

    println!();
    println!("Top Endpoints (10):");

    let mut endpoints: Vec<(String, usize)> = endpoint_counts.into_iter().collect();
    endpoints.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    endpoints.truncate(10);

    for (endpoint, count) in &endpoints {
        println!("  {endpoint:<22} {count:>4} packets");
    }

    Ok(())
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{total_secs}s")
    }
}
