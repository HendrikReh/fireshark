use std::fmt::Write as _;
use std::io::Write;

use colored::Colorize;
use fireshark_core::LayerSpan;

use crate::color;

/// Render a color-coded hex dump of raw packet bytes.
///
/// Each byte is colored based on which layer span it falls within.
/// Format: 16 bytes per line, two groups of 8, with ASCII column.
pub fn render<W: Write>(
    writer: &mut W,
    data: &[u8],
    spans: &[(LayerSpan, &str)],
) -> std::io::Result<()> {
    writeln!(writer, "─── Hex Dump ──────────────────────────────────")?;

    for line_start in (0..data.len()).step_by(16) {
        let line_end = (line_start + 16).min(data.len());
        let line_bytes = &data[line_start..line_end];

        // Offset column
        write!(writer, "{:04x}  ", line_start)?;

        // Hex columns
        let mut hex_part = String::new();
        for (i, &byte) in line_bytes.iter().enumerate() {
            let offset = line_start + i;
            let hex = format!("{byte:02x}");
            let colored_hex = match find_span(offset, spans) {
                Some(protocol) => format!("{}", hex.color(color::protocol_color(protocol))),
                None => format!("{}", hex.dimmed()),
            };
            hex_part.push_str(&colored_hex);
            hex_part.push(' ');
            if i == 7 {
                hex_part.push(' ');
            }
        }
        // Pad if fewer than 16 bytes
        let missing = 16 - line_bytes.len();
        for i in 0..missing {
            hex_part.push_str("   ");
            if line_bytes.len() + i == 8 {
                hex_part.push(' ');
            }
        }

        // ASCII column
        let mut ascii_part = String::new();
        for &byte in line_bytes {
            if (0x20..=0x7E).contains(&byte) {
                let _ = write!(ascii_part, "{}", byte as char);
            } else {
                ascii_part.push('.');
            }
        }

        writeln!(writer, "{} {}", hex_part, ascii_part.dimmed())?;
    }

    // Legend
    render_legend(writer, spans)?;

    Ok(())
}

fn find_span<'a>(offset: usize, spans: &[(LayerSpan, &'a str)]) -> Option<&'a str> {
    spans.iter().rev().find_map(|(span, protocol)| {
        if offset >= span.offset && offset < span.offset + span.len {
            Some(*protocol)
        } else {
            None
        }
    })
}

fn render_legend<W: Write>(writer: &mut W, spans: &[(LayerSpan, &str)]) -> std::io::Result<()> {
    let mut seen = Vec::new();
    let mut legend = String::from("  ");
    for (_, protocol) in spans {
        if !seen.contains(protocol) {
            seen.push(protocol);
            let colored_square = format!("{}", "■".color(color::protocol_color(protocol)));
            let _ = write!(legend, "{colored_square} {protocol}  ");
        }
    }
    writeln!(writer, "{legend}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_hex_dump_for_short_input() {
        colored::control::set_override(false);
        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let spans = [(LayerSpan { offset: 0, len: 4 }, "TCP")];
        let mut output = Vec::new();
        render(&mut output, &data, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("0000"));
        assert!(text.contains("..\"3DU"));
    }

    #[test]
    fn renders_legend_with_unique_protocols() {
        colored::control::set_override(false);
        let spans = [
            (LayerSpan { offset: 0, len: 14 }, "Ethernet"),
            (
                LayerSpan {
                    offset: 14,
                    len: 20,
                },
                "IPv4",
            ),
        ];
        let mut output = Vec::new();
        render_legend(&mut output, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("Ethernet"));
        assert!(text.contains("IPv4"));
    }

    #[test]
    fn empty_data_produces_only_header_and_legend() {
        colored::control::set_override(false);
        let mut output = Vec::new();
        render(&mut output, &[], &[]).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("Hex Dump"));
        assert!(!text.contains("0000"));
    }

    #[test]
    fn renders_exactly_eight_bytes_mid_row_boundary() {
        colored::control::set_override(false);
        let data: [u8; 8] = [0x41; 8];
        let spans = [(LayerSpan { offset: 0, len: 8 }, "TCP")];
        let mut output = Vec::new();
        render(&mut output, &data, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("0000"));
        assert!(text.contains("AAAAAAAA"));
    }

    #[test]
    fn renders_exactly_sixteen_bytes_full_row() {
        colored::control::set_override(false);
        let data: [u8; 16] = [0x42; 16];
        let spans = [(LayerSpan { offset: 0, len: 16 }, "UDP")];
        let mut output = Vec::new();
        render(&mut output, &data, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("0000"));
        assert!(text.contains("BBBBBBBBBBBBBBBB"));
        // Should be exactly one data line (no 0010 offset)
        assert!(!text.contains("0010"));
    }

    #[test]
    fn renders_multi_row_with_twenty_bytes() {
        colored::control::set_override(false);
        let data: [u8; 20] = [0x43; 20];
        let spans = [(LayerSpan { offset: 0, len: 20 }, "TCP")];
        let mut output = Vec::new();
        render(&mut output, &data, &spans).unwrap();
        let text = String::from_utf8(output).unwrap();

        // First row
        assert!(text.contains("0000"));
        // Second row
        assert!(text.contains("0010"));
    }

    #[test]
    fn find_span_returns_innermost_layer() {
        // Ethernet covers 0..14, IPv4 covers 14..34, TCP covers 34..54
        // Byte at offset 0 is only in Ethernet
        // Byte at offset 14 is in both Ethernet (if it were 0..34) and IPv4
        let spans = [
            (LayerSpan { offset: 0, len: 54 }, "Ethernet"),
            (
                LayerSpan {
                    offset: 14,
                    len: 40,
                },
                "IPv4",
            ),
            (
                LayerSpan {
                    offset: 34,
                    len: 20,
                },
                "TCP",
            ),
        ];

        // Byte 0 is in Ethernet only
        assert_eq!(find_span(0, &spans), Some("Ethernet"));
        // Byte 14 is in both Ethernet and IPv4; innermost (IPv4) should win
        assert_eq!(find_span(14, &spans), Some("IPv4"));
        // Byte 34 is in Ethernet, IPv4, and TCP; innermost (TCP) should win
        assert_eq!(find_span(34, &spans), Some("TCP"));
    }
}
