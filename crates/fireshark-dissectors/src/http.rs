use fireshark_core::{HttpLayer, Layer};

use crate::DecodeError;

const MIN_PAYLOAD_LEN: usize = 4;

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
    b"CONNECT ",
];

/// Check whether the first bytes of `bytes` look like an HTTP request or
/// response.  Exported so the orchestrator can gate dispatch.
pub fn is_http_signature(bytes: &[u8]) -> bool {
    if bytes.len() < MIN_PAYLOAD_LEN {
        return false;
    }
    if bytes.starts_with(b"HTTP/") {
        return true;
    }
    HTTP_METHODS.iter().any(|m| bytes.starts_with(m))
}

/// Parsed first-line fields for either a request or response.
struct FirstLine {
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    status_code: Option<u16>,
    reason: Option<String>,
}

pub fn parse(bytes: &[u8], _offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_PAYLOAD_LEN {
        return Err(DecodeError::Truncated {
            layer: "HTTP",
            offset: _offset + bytes.len(),
        });
    }

    let text = lossy_ascii(bytes);

    let is_response = text.starts_with("HTTP/");
    let first = if is_response {
        parse_status_line(&text)
    } else {
        parse_request_line(&text)
    };

    let (host, content_type, content_length) = extract_headers(&text);

    Ok(Layer::Http(HttpLayer {
        is_request: !is_response,
        method: first.method,
        uri: first.uri,
        version: first.version.unwrap_or_else(|| String::from("HTTP/1.0")),
        status_code: first.status_code,
        reason: first.reason,
        host,
        content_type,
        content_length,
    }))
}

/// Convert bytes to an ASCII-lossy string (non-ASCII bytes become '?').
fn lossy_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { '?' })
        .collect()
}

/// Parse `METHOD SP URI SP VERSION\r\n`.
fn parse_request_line(text: &str) -> FirstLine {
    let first_line = text.lines().next().unwrap_or("");
    let first_line = first_line.trim_end_matches('\r');
    let mut parts = first_line.splitn(3, ' ');
    FirstLine {
        method: parts.next().map(String::from),
        uri: parts.next().map(String::from),
        version: parts.next().map(String::from),
        status_code: None,
        reason: None,
    }
}

/// Parse `VERSION SP STATUS SP REASON\r\n`.
fn parse_status_line(text: &str) -> FirstLine {
    let first_line = text.lines().next().unwrap_or("");
    let first_line = first_line.trim_end_matches('\r');
    let mut parts = first_line.splitn(3, ' ');
    FirstLine {
        method: None,
        uri: None,
        version: parts.next().map(String::from),
        status_code: parts.next().and_then(|s| s.parse::<u16>().ok()),
        reason: parts.next().map(String::from),
    }
}

/// Scan headers after the first line, extracting Host, Content-Type, and
/// Content-Length.  Stops at `\r\n\r\n` or end of input.
fn extract_headers(text: &str) -> (Option<String>, Option<String>, Option<u64>) {
    let mut host = None;
    let mut content_type = None;
    let mut content_length = None;

    // Skip the first line (request/status line).
    let header_start = match text.find('\n') {
        Some(pos) => pos + 1,
        None => return (host, content_type, content_length),
    };

    for line in text[header_start..].lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse::<u64>().ok();
            }
        }
    }

    (host, content_type, content_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_http_get_request() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\n";
        let layer = parse(payload, 0).unwrap();
        match layer {
            Layer::Http(http) => {
                assert!(http.is_request);
                assert_eq!(http.method.as_deref(), Some("GET"));
                assert_eq!(http.uri.as_deref(), Some("/"));
                assert_eq!(http.version, "HTTP/1.1");
                assert_eq!(http.status_code, None);
                assert_eq!(http.host.as_deref(), Some("example.com"));
                assert_eq!(http.content_type.as_deref(), Some("text/html"));
            }
            other => panic!("expected Http layer, got: {other:?}"),
        }
    }

    #[test]
    fn http_response_parses_status() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n";
        let layer = parse(payload, 0).unwrap();
        match layer {
            Layer::Http(http) => {
                assert!(!http.is_request);
                assert_eq!(http.method, None);
                assert_eq!(http.uri, None);
                assert_eq!(http.version, "HTTP/1.1");
                assert_eq!(http.status_code, Some(200));
                assert_eq!(http.reason.as_deref(), Some("OK"));
                assert_eq!(http.content_type.as_deref(), Some("text/html"));
                assert_eq!(http.content_length, Some(1234));
            }
            other => panic!("expected Http layer, got: {other:?}"),
        }
    }

    #[test]
    fn is_http_signature_detects_methods() {
        assert!(is_http_signature(b"GET / HTTP/1.1\r\n"));
        assert!(is_http_signature(b"POST /submit HTTP/1.1\r\n"));
        assert!(is_http_signature(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_http_signature(b"DELETE /item HTTP/1.1\r\n"));
        assert!(is_http_signature(b"OPTIONS * HTTP/1.1\r\n"));
    }

    #[test]
    fn is_http_signature_rejects_non_http() {
        assert!(!is_http_signature(b"\x16\x03\x01")); // TLS
        assert!(!is_http_signature(b"abc"));
        assert!(!is_http_signature(b""));
        assert!(!is_http_signature(b"\x00\x01\x02\x03\x04\x05"));
    }

    #[test]
    fn truncated_payload_returns_error() {
        let result = parse(b"GE", 10);
        assert!(matches!(result, Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn post_request_with_content_length() {
        let payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        let layer = parse(payload, 0).unwrap();
        match layer {
            Layer::Http(http) => {
                assert!(http.is_request);
                assert_eq!(http.method.as_deref(), Some("POST"));
                assert_eq!(http.uri.as_deref(), Some("/api/data"));
                assert_eq!(http.host.as_deref(), Some("api.example.com"));
                assert_eq!(http.content_type.as_deref(), Some("application/json"));
                assert_eq!(http.content_length, Some(42));
            }
            other => panic!("expected Http layer, got: {other:?}"),
        }
    }

    #[test]
    fn headers_case_insensitive() {
        let payload = b"GET / HTTP/1.1\r\nhOsT: Mixed.Case.Com\r\nCONTENT-TYPE: text/plain\r\ncontent-length: 99\r\n\r\n";
        let layer = parse(payload, 0).unwrap();
        match layer {
            Layer::Http(http) => {
                assert_eq!(http.host.as_deref(), Some("Mixed.Case.Com"));
                assert_eq!(http.content_type.as_deref(), Some("text/plain"));
                assert_eq!(http.content_length, Some(99));
            }
            other => panic!("expected Http layer, got: {other:?}"),
        }
    }
}
