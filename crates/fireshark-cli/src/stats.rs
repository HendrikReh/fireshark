//! Capture statistics: packet count, duration, protocol distribution, top endpoints.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use fireshark_backend::{BackendCapture, BackendKind};
use fireshark_core::TrackingPipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::json::{EndpointJson, ProtocolJson, StatsJson};
use crate::timestamp;

pub fn run(path: &Path, backend: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let kind: BackendKind = backend
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    match kind {
        BackendKind::Native => run_native(path, json),
        BackendKind::Tshark => run_tshark(path, json),
    }
}

fn run_native(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;

    let mut packet_count: usize = 0;
    let mut first_ts: Option<Duration> = None;
    let mut last_ts: Option<Duration> = None;
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoint_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    for result in pipeline.by_ref() {
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

    let tracker = pipeline.into_tracker();

    let mut protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
    protocols.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut endpoints: Vec<(String, usize)> = endpoint_counts.into_iter().collect();
    endpoints.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    endpoints.truncate(10);

    if json {
        let duration_seconds = match (first_ts, last_ts) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_secs_f64()),
            _ => None,
        };
        let stats = StatsJson {
            packet_count,
            stream_count: tracker.stream_count(),
            duration_seconds,
            first_timestamp: first_ts.map(timestamp::format_utc),
            last_timestamp: last_ts.map(timestamp::format_utc),
            protocols: protocols
                .iter()
                .map(|(name, count)| {
                    let pct = if packet_count > 0 {
                        (*count as f64 / packet_count as f64) * 100.0
                    } else {
                        0.0
                    };
                    ProtocolJson {
                        name: name.clone(),
                        count: *count,
                        percent: pct,
                    }
                })
                .collect(),
            top_endpoints: endpoints
                .iter()
                .map(|(endpoint, count)| EndpointJson {
                    endpoint: endpoint.clone(),
                    count: *count,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string(&stats).unwrap());
    } else {
        println!("Capture Statistics");
        println!("{}", "\u{2500}".repeat(38));

        println!("Packets:    {packet_count}");
        println!("Streams:    {}", tracker.stream_count());

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

        for (endpoint, count) in &endpoints {
            println!("  {endpoint:<22} {count:>4} packets");
        }
    }

    Ok(())
}

fn run_tshark(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let capture = BackendCapture::open(path, BackendKind::Tshark)?;

    let packet_count = capture.packet_count();

    // Compute timestamps from backend packets.
    let mut first_ts: Option<Duration> = None;
    let mut last_ts: Option<Duration> = None;
    for pkt in capture.packets() {
        if let Some(ts) = pkt.summary.timestamp {
            if first_ts.is_none() || Some(ts) < first_ts {
                first_ts = Some(ts);
            }
            if last_ts.is_none() || Some(ts) > last_ts {
                last_ts = Some(ts);
            }
        }
    }

    if json {
        let duration_seconds = match (first_ts, last_ts) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_secs_f64()),
            _ => None,
        };
        let protocol_counts_vec = capture.protocol_counts();
        let endpoint_counts_vec = capture.endpoint_counts();
        let stats = StatsJson {
            packet_count,
            stream_count: 0,
            duration_seconds,
            first_timestamp: first_ts.map(timestamp::format_utc),
            last_timestamp: last_ts.map(timestamp::format_utc),
            protocols: protocol_counts_vec
                .iter()
                .map(|(name, count)| {
                    let pct = if packet_count > 0 {
                        (*count as f64 / packet_count as f64) * 100.0
                    } else {
                        0.0
                    };
                    ProtocolJson {
                        name: name.clone(),
                        count: *count,
                        percent: pct,
                    }
                })
                .collect(),
            top_endpoints: endpoint_counts_vec
                .iter()
                .take(10)
                .map(|(endpoint, count)| EndpointJson {
                    endpoint: endpoint.clone(),
                    count: *count,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string(&stats).unwrap());
    } else {
        println!("Capture Statistics");
        println!("{}", "\u{2500}".repeat(38));

        println!("Packets:    {packet_count}");
        println!("Streams:    -");

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

        for (protocol, count) in capture.protocol_counts() {
            let pct = if packet_count > 0 {
                (*count as f64 / packet_count as f64) * 100.0
            } else {
                0.0
            };
            println!("  {protocol:<10} {count:>4}  ({pct:>4.1}%)");
        }

        println!();
        println!("Top Endpoints (10):");

        for (endpoint, count) in capture.endpoint_counts().iter().take(10) {
            println!("  {endpoint:<22} {count:>4} packets");
        }
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
