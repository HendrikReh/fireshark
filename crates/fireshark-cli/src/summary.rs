//! Packet summary listing with protocol coloring and optional display filter.

use std::path::Path;

use fireshark_backend::{BackendCapture, BackendKind};
use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

pub fn run(
    path: &Path,
    filter: Option<&str>,
    backend: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let kind: BackendKind = backend
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    match kind {
        BackendKind::Native => run_native(path, filter),
        BackendKind::Tshark => run_tshark(path, filter),
    }
}

fn run_native(path: &Path, filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let filter_expr = filter.map(fireshark_filter::parse).transpose()?;

    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", index + 1);
                continue;
            }
        };

        if let Some(ref expr) = filter_expr
            && !fireshark_filter::evaluate(expr, &decoded)
        {
            continue;
        }

        let summary = decoded.summary();
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

    Ok(())
}

fn run_tshark(path: &Path, filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if filter.is_some() {
        return Err("display filters are not yet supported with the tshark backend".into());
    }

    let capture = BackendCapture::open(path, BackendKind::Tshark)?;

    for packet in capture.packets() {
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

    Ok(())
}
