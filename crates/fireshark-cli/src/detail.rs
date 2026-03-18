//! Single-packet detail view with decoded layer tree and color-coded hex dump.

use std::io::{self, Write};
use std::path::Path;

use colored::Colorize;
use fireshark_core::{DecodedFrame, LayerSpan, Pipeline};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::hexdump;
use crate::render;
use crate::timestamp;

pub fn run(path: &Path, packet_number: usize) -> Result<(), Box<dyn std::error::Error>> {
    if packet_number == 0 {
        return Err("packet number must be >= 1".into());
    }

    let reader = CaptureReader::open(path)?;
    let index = packet_number - 1;

    let decoded = Pipeline::new(reader, decode_packet)
        .nth(index)
        .ok_or_else(|| format!("packet {packet_number} not found (capture has fewer packets)"))?
        .map_err(|e| format!("decode error at packet {packet_number}: {e}"))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();

    render_header(&mut out, &decoded, packet_number)?;
    render_layer_tree(&mut out, &decoded)?;

    let span_colors: Vec<(LayerSpan, &str)> = decoded
        .packet()
        .layers()
        .iter()
        .zip(decoded.packet().spans())
        .map(|(layer, span)| (*span, layer.name()))
        .collect();
    hexdump::render(&mut out, decoded.frame().data(), &span_colors)?;

    Ok(())
}

fn render_header<W: Write>(
    w: &mut W,
    decoded: &DecodedFrame,
    packet_number: usize,
) -> io::Result<()> {
    let len = decoded.frame().captured_len();
    let ts = match decoded.frame().timestamp() {
        Some(d) => timestamp::format_utc(d),
        None => String::from("-"),
    };
    writeln!(w, "Packet {packet_number} · {len} bytes · {ts}")?;
    writeln!(w, "─────────────────────────────────────────────────")
}

fn render_layer_tree<W: Write>(w: &mut W, decoded: &DecodedFrame) -> io::Result<()> {
    for layer in decoded.packet().layers() {
        render::render_layer(w, layer)?;
    }
    for issue in decoded.packet().issues() {
        let kind = match issue.kind() {
            fireshark_core::DecodeIssueKind::Truncated => "Truncated",
            fireshark_core::DecodeIssueKind::Malformed => "Malformed",
            fireshark_core::DecodeIssueKind::ChecksumMismatch => "Checksum mismatch",
        };
        writeln!(w, "{} {} at offset {}", "⚠".red(), kind, issue.offset())?;
    }
    Ok(())
}
