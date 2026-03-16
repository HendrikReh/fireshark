use std::fmt::Write as _;
use std::io::Write;

use colored::Colorize;
use fireshark_core::LayerSpan;

use crate::color;

/// Pre-computed hex strings for bytes 0x00..=0xFF, avoiding per-byte format! allocations.
const HEX_TABLE: [&str; 256] = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
];

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

        // Hex columns — write colored hex bytes directly into the buffer
        // to avoid per-byte String allocations
        let mut hex_part = String::with_capacity(80);
        for (i, &byte) in line_bytes.iter().enumerate() {
            let offset = line_start + i;
            let hex_str = HEX_TABLE[byte as usize];
            let colored = match find_span(offset, spans) {
                Some(protocol) => hex_str.color(color::protocol_color(protocol)).to_string(),
                None => hex_str.dimmed().to_string(),
            };
            hex_part.push_str(&colored);
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
