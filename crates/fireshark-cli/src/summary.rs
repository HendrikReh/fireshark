//! Packet summary listing with protocol coloring and optional display filter.

use std::path::Path;

use fireshark_backend::{BackendCapture, BackendKind};
use fireshark_core::TrackingPipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::json::PacketJson;
use crate::timestamp;

pub fn run(
    path: &Path,
    filter: Option<&str>,
    backend: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let kind: BackendKind = backend
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    match kind {
        BackendKind::Native => run_native(path, filter, json),
        BackendKind::Tshark => run_tshark(path, filter, json),
    }
}

fn run_native(
    path: &Path,
    filter: Option<&str>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter_expr = filter.map(fireshark_filter::compile).transpose()?;

    let reader = CaptureReader::open(path)?;
    for (index, decoded) in TrackingPipeline::new(reader, decode_packet).enumerate() {
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", index + 1);
                continue;
            }
        };

        if let Some(ref expr) = filter_expr
            && !fireshark_filter::matches(expr, &decoded)
        {
            continue;
        }

        let summary = decoded.summary();

        if json {
            let ts = summary.timestamp.map(timestamp::format_utc);
            let pkt = PacketJson {
                index: index + 1,
                timestamp: ts,
                protocol: summary.protocol,
                source: summary.source,
                destination: summary.destination,
                length: summary.length,
                stream_id: decoded.stream_id(),
            };
            println!("{}", serde_json::to_string(&pkt).unwrap());
        } else {
            let ts = match summary.timestamp {
                Some(duration) => timestamp::format_utc(duration),
                None => String::from("-"),
            };
            let line = format!(
                "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
                index + 1,
                ts,
                summary.protocol,
                summary.source,
                summary.destination,
                summary.length
            );
            println!("{}", color::colorize(&summary.protocol, &line));
        }
    }

    Ok(())
}

fn run_tshark(
    path: &Path,
    filter: Option<&str>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if filter.is_some() {
        return Err("display filters are not yet supported with the tshark backend".into());
    }

    let capture = BackendCapture::open(path, BackendKind::Tshark)?;

    for packet in capture.packets() {
        if json {
            let ts = packet.summary.timestamp.map(timestamp::format_utc);
            let pkt = PacketJson {
                index: packet.index + 1,
                timestamp: ts,
                protocol: packet.summary.protocol.clone(),
                source: packet.summary.source.clone(),
                destination: packet.summary.destination.clone(),
                length: packet.summary.length,
                stream_id: None,
            };
            println!("{}", serde_json::to_string(&pkt).unwrap());
        } else {
            let ts = match packet.summary.timestamp {
                Some(duration) => timestamp::format_utc(duration),
                None => String::from("-"),
            };
            let line = format!(
                "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
                packet.index + 1,
                ts,
                packet.summary.protocol,
                packet.summary.source,
                packet.summary.destination,
                packet.summary.length
            );
            println!("{}", color::colorize(&packet.summary.protocol, &line));
        }
    }

    Ok(())
}
