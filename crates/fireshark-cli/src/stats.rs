//! Capture statistics: packet count, duration, protocol distribution, top endpoints.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use fireshark_backend::{BackendCapture, BackendKind};
use fireshark_core::{TrackingPipeline, format_utc};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::json::{EndpointJson, ProtocolJson, StatsJson};

/// Computed statistics ready for rendering.
struct CaptureStats {
    packet_count: usize,
    stream_count: Option<usize>,
    first_ts: Option<Duration>,
    last_ts: Option<Duration>,
    protocols: Vec<(String, usize)>,
    endpoints: Vec<(String, usize)>,
}

impl CaptureStats {
    fn render_json(&self) {
        let duration_seconds = match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_secs_f64()),
            _ => None,
        };
        let stats = StatsJson {
            packet_count: self.packet_count,
            stream_count: self.stream_count.unwrap_or(0),
            duration_seconds,
            first_timestamp: self.first_ts.map(format_utc),
            last_timestamp: self.last_ts.map(format_utc),
            protocols: self
                .protocols
                .iter()
                .map(|(name, count)| {
                    let pct = if self.packet_count > 0 {
                        (*count as f64 / self.packet_count as f64) * 100.0
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
            top_endpoints: self
                .endpoints
                .iter()
                .map(|(endpoint, count)| EndpointJson {
                    endpoint: endpoint.clone(),
                    count: *count,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string(&stats).unwrap());
    }

    fn render_human(&self) {
        println!("Capture Statistics");
        println!("{}", "\u{2500}".repeat(38));

        println!("Packets:    {}", self.packet_count);
        match self.stream_count {
            Some(n) => println!("Streams:    {n}"),
            None => println!("Streams:    -"),
        }

        match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => {
                let duration = last.saturating_sub(first);
                println!(
                    "Duration:   {} ({} \u{2192} {})",
                    format_duration(duration),
                    format_utc(first),
                    format_utc(last)
                );
            }
            _ => {
                println!("Duration:   -");
            }
        }

        println!();
        println!("Protocol Distribution:");

        for (protocol, count) in &self.protocols {
            let pct = if self.packet_count > 0 {
                (*count as f64 / self.packet_count as f64) * 100.0
            } else {
                0.0
            };
            println!("  {protocol:<10} {count:>4}  ({pct:>4.1}%)");
        }

        println!();
        println!("Top Endpoints (10):");

        for (endpoint, count) in &self.endpoints {
            println!("  {endpoint:<22} {count:>4} packets");
        }
    }
}

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

    let mut frame_count: usize = 0;
    let mut packet_count: usize = 0;
    let mut first_ts: Option<Duration> = None;
    let mut last_ts: Option<Duration> = None;
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoint_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut pipeline = TrackingPipeline::new(reader, decode_packet);

    for result in pipeline.by_ref() {
        frame_count += 1;
        let decoded = match result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {frame_count}: {e}");
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

    let stats = CaptureStats {
        packet_count,
        stream_count: Some(tracker.stream_count()),
        first_ts,
        last_ts,
        protocols,
        endpoints,
    };

    if json {
        stats.render_json();
    } else {
        stats.render_human();
    }

    Ok(())
}

fn run_tshark(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let capture = BackendCapture::open(path, BackendKind::Tshark)?;

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

    let stats = CaptureStats {
        packet_count: capture.packet_count(),
        stream_count: None,
        first_ts,
        last_ts,
        protocols: capture.protocol_counts().to_vec(),
        endpoints: capture.endpoint_counts().iter().take(10).cloned().collect(),
    };

    if json {
        stats.render_json();
    } else {
        stats.render_human();
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
