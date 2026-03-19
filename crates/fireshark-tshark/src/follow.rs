//! Stream reassembly via tshark's `-z follow` statistics.

use std::path::Path;
use std::process::Command;

use crate::command::{DEFAULT_TIMEOUT, run_with_timeout};
use crate::reassembly::{Direction, FollowMode, StreamPayload, StreamSegment};

use crate::TsharkError;

/// Execute tshark's follow mode and parse the reassembled stream.
///
/// For [`FollowMode::Tcp`], runs `tshark -z follow,tcp,raw,<stream_id> -q`
/// and decodes hex-encoded payload lines.
///
/// For [`FollowMode::Http`], runs `tshark -z follow,http,ascii,<stream_id> -q`
/// and collects ASCII payload lines.
///
/// Paths are passed via `Command::arg` (no shell), so injection is not possible.
pub fn follow_stream(
    tshark_path: &Path,
    capture_path: &Path,
    stream_id: u32,
    mode: FollowMode,
) -> Result<StreamPayload, TsharkError> {
    let follow_arg = match mode {
        FollowMode::Tcp => format!("follow,tcp,raw,{stream_id}"),
        FollowMode::Http => format!("follow,http,ascii,{stream_id}"),
    };

    let mut cmd = Command::new(tshark_path);
    cmd.arg("-r")
        .arg(capture_path)
        .arg("-z")
        .arg(&follow_arg)
        .arg("-q");

    let output = run_with_timeout(cmd, DEFAULT_TIMEOUT)?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| TsharkError::ParseOutput(format!("tshark output is not valid UTF-8: {e}")))?;

    match mode {
        FollowMode::Tcp => parse_follow_raw(&stdout, stream_id),
        FollowMode::Http => parse_follow_ascii(&stdout, stream_id),
    }
}

/// Parse output from `tshark -z follow,tcp,raw,N -q`.
///
/// The output is structured as:
/// ```text
/// ===================================================================
/// Follow: tcp,raw
/// Filter: tcp.stream eq 0
/// Node 0: 192.168.1.2:51514
/// Node 1: 198.51.100.20:443
/// ===================================================================
/// 48656c6c6f
/// \t576f726c64
/// ===================================================================
/// ```
///
/// Lines between the second and third `===` markers contain the stream data.
/// Tab-prefixed lines are server-to-client (Node 1); others are client-to-server (Node 0).
/// Each line is a hex-encoded byte string.
pub fn parse_follow_raw(output: &str, stream_id: u32) -> Result<StreamPayload, TsharkError> {
    let (client, server, data_lines) = parse_follow_header_and_data(output)?;

    let mut segments = Vec::new();
    for line in data_lines {
        if line.is_empty() {
            continue;
        }
        let (direction, hex_str) = if let Some(stripped) = line.strip_prefix('\t') {
            (Direction::ServerToClient, stripped)
        } else {
            (Direction::ClientToServer, line)
        };

        let data = decode_hex(hex_str)
            .map_err(|e| TsharkError::ParseOutput(format!("invalid hex in follow output: {e}")))?;

        segments.push(StreamSegment { direction, data });
    }

    Ok(StreamPayload {
        stream_id,
        client,
        server,
        segments,
    })
}

/// Parse output from `tshark -z follow,http,ascii,N -q`.
///
/// Similar structure to raw mode, but data lines contain ASCII text
/// instead of hex. Tab-prefixed lines are server-to-client.
pub fn parse_follow_ascii(output: &str, stream_id: u32) -> Result<StreamPayload, TsharkError> {
    let (client, server, data_lines) = parse_follow_header_and_data(output)?;

    let mut segments = Vec::new();
    for line in data_lines {
        // In ASCII mode, empty lines can be part of HTTP headers/body.
        let (direction, text) = if let Some(stripped) = line.strip_prefix('\t') {
            (Direction::ServerToClient, stripped)
        } else {
            (Direction::ClientToServer, line)
        };

        let mut data = text.as_bytes().to_vec();
        data.push(b'\n');

        segments.push(StreamSegment { direction, data });
    }

    Ok(StreamPayload {
        stream_id,
        client,
        server,
        segments,
    })
}

/// Extract the header fields (Node 0, Node 1) and the data lines from
/// tshark follow output. Returns `(client, server, data_lines)`.
fn parse_follow_header_and_data(output: &str) -> Result<(String, String, Vec<&str>), TsharkError> {
    let separator = "===";
    let mut sections: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = Vec::new();

    for line in output.lines() {
        if line.starts_with(separator) {
            sections.push(std::mem::take(&mut current));
        } else {
            current.push(line);
        }
    }
    // Push any remaining lines after the last separator.
    if !current.is_empty() {
        sections.push(current);
    }

    // We expect at least: [pre-header], [header], [data], [trailing]
    // sections[0] = lines before first ===  (usually empty)
    // sections[1] = header lines (Follow, Filter, Node 0, Node 1)
    // sections[2] = data lines
    if sections.len() < 3 {
        return Err(TsharkError::ParseOutput(
            "follow output missing expected === delimiters".into(),
        ));
    }

    let header_lines = &sections[1];
    let mut client = String::new();
    let mut server = String::new();

    for line in header_lines {
        if let Some(addr) = line.strip_prefix("Node 0: ") {
            client = addr.trim().to_string();
        } else if let Some(addr) = line.strip_prefix("Node 1: ") {
            server = addr.trim().to_string();
        }
    }

    let data_lines = sections[2].clone();

    Ok((client, server, data_lines))
}

/// Decode a hex string into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_raw_output() -> String {
        [
            "===================================================================",
            "Follow: tcp,raw",
            "Filter: tcp.stream eq 0",
            "Node 0: 192.168.1.2:51514",
            "Node 1: 198.51.100.20:443",
            "===================================================================",
            "48656c6c6f",
            "\t576f726c64",
            "===================================================================",
        ]
        .join("\n")
    }

    fn sample_ascii_output() -> String {
        [
            "===================================================================",
            "Follow: http,ascii",
            "Filter: tcp.stream eq 0",
            "Node 0: 192.168.1.2:51514",
            "Node 1: 198.51.100.20:80",
            "===================================================================",
            "GET / HTTP/1.1",
            "Host: example.com",
            "\tHTTP/1.1 200 OK",
            "\tContent-Length: 5",
            "\tHello",
            "===================================================================",
        ]
        .join("\n")
    }

    #[test]
    fn parse_raw_follow_output() {
        let payload = parse_follow_raw(&sample_raw_output(), 0).unwrap();
        assert_eq!(payload.stream_id, 0);
        assert_eq!(payload.client, "192.168.1.2:51514");
        assert_eq!(payload.server, "198.51.100.20:443");
        assert_eq!(payload.segments.len(), 2);

        assert_eq!(payload.segments[0].direction, Direction::ClientToServer);
        assert_eq!(payload.segments[0].data, b"Hello");

        assert_eq!(payload.segments[1].direction, Direction::ServerToClient);
        assert_eq!(payload.segments[1].data, b"World");
    }

    #[test]
    fn parse_ascii_follow_output() {
        let payload = parse_follow_ascii(&sample_ascii_output(), 0).unwrap();
        assert_eq!(payload.stream_id, 0);
        assert_eq!(payload.client, "192.168.1.2:51514");
        assert_eq!(payload.server, "198.51.100.20:80");

        // Client segments: "GET / HTTP/1.1\n" and "Host: example.com\n"
        let client_segments: Vec<_> = payload
            .segments
            .iter()
            .filter(|s| s.direction == Direction::ClientToServer)
            .collect();
        assert_eq!(client_segments.len(), 2);
        assert_eq!(client_segments[0].data, b"GET / HTTP/1.1\n");
        assert_eq!(client_segments[1].data, b"Host: example.com\n");

        // Server segments: "HTTP/1.1 200 OK\n", "Content-Length: 5\n", "Hello\n"
        let server_segments: Vec<_> = payload
            .segments
            .iter()
            .filter(|s| s.direction == Direction::ServerToClient)
            .collect();
        assert_eq!(server_segments.len(), 3);
        assert_eq!(server_segments[0].data, b"HTTP/1.1 200 OK\n");
    }

    #[test]
    fn parse_empty_stream() {
        let output = [
            "===================================================================",
            "Follow: tcp,raw",
            "Filter: tcp.stream eq 5",
            "Node 0: 10.0.0.1:1234",
            "Node 1: 10.0.0.2:80",
            "===================================================================",
            "===================================================================",
        ]
        .join("\n");

        let payload = parse_follow_raw(&output, 5).unwrap();
        assert_eq!(payload.stream_id, 5);
        assert!(payload.segments.is_empty());
    }

    #[test]
    fn decode_hex_basic() {
        assert_eq!(decode_hex("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert!(decode_hex("zz").is_err());
        assert!(decode_hex("abc").is_err()); // odd length
    }

    #[test]
    fn missing_delimiters_errors() {
        let output = "no delimiters here";
        assert!(parse_follow_raw(output, 0).is_err());
    }
}
