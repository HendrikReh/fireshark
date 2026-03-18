use fireshark_core::{Layer, TlsClientHelloLayer, TlsServerHelloLayer};

use crate::DecodeError;

/// Minimum bytes needed: 5 (TLS record header) + 4 (handshake header) = 9.
const MIN_RECORD_LEN: usize = 9;

/// Maximum number of cipher suites to parse.
const MAX_CIPHER_SUITES: usize = 200;

/// Maximum number of extensions to parse.
const MAX_EXTENSIONS: usize = 50;

/// Parse a TLS ClientHello or ServerHello from a TCP payload.
///
/// `bytes` is the application payload (starting at the TLS record header).
/// `offset` is the absolute byte offset within the frame for error reporting.
pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < MIN_RECORD_LEN {
        return Err(DecodeError::Truncated {
            layer: "TLS",
            offset: offset + bytes.len(),
        });
    }

    let record_version = u16::from_be_bytes([bytes[1], bytes[2]]);
    let handshake_type = bytes[5];

    match handshake_type {
        0x01 => Ok(Layer::TlsClientHello(parse_client_hello(
            bytes,
            record_version,
        ))),
        0x02 => Ok(Layer::TlsServerHello(parse_server_hello(
            bytes,
            record_version,
        ))),
        _ => Err(DecodeError::Malformed("unsupported TLS handshake type")),
    }
}

fn parse_client_hello(bytes: &[u8], record_version: u16) -> TlsClientHelloLayer {
    let mut layer = TlsClientHelloLayer {
        record_version,
        client_version: 0,
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        sni: None,
        alpn: Vec::new(),
        supported_versions: Vec::new(),
        signature_algorithms: Vec::new(),
        key_share_groups: Vec::new(),
    };

    // Client version at offset 9 (2 bytes)
    if bytes.len() < 11 {
        return layer;
    }
    layer.client_version = u16::from_be_bytes([bytes[9], bytes[10]]);

    // Random: 32 bytes at offset 11, skip to offset 43
    // Session ID length at offset 43
    if bytes.len() < 44 {
        return layer;
    }
    let session_id_len = bytes[43] as usize;
    let mut pos = 44 + session_id_len;

    if pos > bytes.len() {
        return layer;
    }

    // Cipher suites: 2-byte length, then 2-byte entries
    if pos + 2 > bytes.len() {
        return layer;
    }
    let cs_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    let cs_end = pos + cs_len;
    if cs_end > bytes.len() {
        return layer;
    }
    let cs_count = cs_len / 2;
    let cs_limit = cs_count.min(MAX_CIPHER_SUITES);
    layer.cipher_suites.reserve(cs_limit);
    for i in 0..cs_limit {
        let idx = pos + i * 2;
        layer
            .cipher_suites
            .push(u16::from_be_bytes([bytes[idx], bytes[idx + 1]]));
    }
    pos = cs_end;

    // Compression methods: 1-byte length, then 1-byte entries
    if pos + 1 > bytes.len() {
        return layer;
    }
    let cm_len = bytes[pos] as usize;
    pos += 1;
    let cm_end = pos + cm_len;
    if cm_end > bytes.len() {
        return layer;
    }
    layer.compression_methods = bytes[pos..cm_end].to_vec();
    pos = cm_end;

    // Extensions: 2-byte length, then extension entries
    if pos + 2 > bytes.len() {
        return layer;
    }
    let ext_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(bytes.len());

    parse_extensions_client(bytes, pos, ext_end, &mut layer);
    layer
}

fn parse_server_hello(bytes: &[u8], record_version: u16) -> TlsServerHelloLayer {
    let mut layer = TlsServerHelloLayer {
        record_version,
        server_version: 0,
        cipher_suite: 0,
        compression_method: 0,
        selected_version: None,
        alpn: None,
        key_share_group: None,
    };

    // Server version at offset 9 (2 bytes)
    if bytes.len() < 11 {
        return layer;
    }
    layer.server_version = u16::from_be_bytes([bytes[9], bytes[10]]);

    // Random: 32 bytes at offset 11, skip to offset 43
    // Session ID length at offset 43
    if bytes.len() < 44 {
        return layer;
    }
    let session_id_len = bytes[43] as usize;
    let mut pos = 44 + session_id_len;

    if pos > bytes.len() {
        return layer;
    }

    // Cipher suite: single 2-byte value
    if pos + 2 > bytes.len() {
        return layer;
    }
    layer.cipher_suite = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;

    // Compression method: single 1-byte value
    if pos + 1 > bytes.len() {
        return layer;
    }
    layer.compression_method = bytes[pos];
    pos += 1;

    // Extensions: 2-byte length, then extension entries
    if pos + 2 > bytes.len() {
        return layer;
    }
    let ext_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(bytes.len());

    parse_extensions_server(bytes, pos, ext_end, &mut layer);
    layer
}

fn parse_extensions_client(
    bytes: &[u8],
    start: usize,
    end: usize,
    layer: &mut TlsClientHelloLayer,
) {
    let mut pos = start;
    let mut count = 0;

    while pos + 4 <= end && count < MAX_EXTENSIONS {
        let ext_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let ext_len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        pos += 4;
        let ext_end = pos + ext_len;
        if ext_end > end {
            break;
        }

        match ext_type {
            0x0000 => {
                // SNI
                layer.sni = parse_sni(bytes, pos, ext_end);
            }
            0x0010 => {
                // ALPN
                layer.alpn = parse_alpn_client(bytes, pos, ext_end);
            }
            0x002B => {
                // Supported versions (ClientHello)
                layer.supported_versions = parse_supported_versions_client(bytes, pos, ext_end);
            }
            0x000D => {
                // Signature algorithms
                layer.signature_algorithms = parse_sig_algs(bytes, pos, ext_end);
            }
            0x0033 => {
                // Key share (ClientHello)
                layer.key_share_groups = parse_key_share_client(bytes, pos, ext_end);
            }
            _ => {}
        }

        pos = ext_end;
        count += 1;
    }
}

fn parse_extensions_server(
    bytes: &[u8],
    start: usize,
    end: usize,
    layer: &mut TlsServerHelloLayer,
) {
    let mut pos = start;
    let mut count = 0;

    while pos + 4 <= end && count < MAX_EXTENSIONS {
        let ext_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let ext_len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        pos += 4;
        let ext_end = pos + ext_len;
        if ext_end > end {
            break;
        }

        match ext_type {
            0x0010 => {
                // ALPN
                layer.alpn = parse_alpn_server(bytes, pos, ext_end);
            }
            0x002B => {
                // Supported versions (ServerHello) — single 2-byte value, no length prefix
                if pos + 2 <= ext_end {
                    layer.selected_version = Some(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
                }
            }
            0x0033 => {
                // Key share (ServerHello) — single entry
                if pos + 4 <= ext_end {
                    layer.key_share_group = Some(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
                }
            }
            _ => {}
        }

        pos = ext_end;
        count += 1;
    }
}

/// Parse the SNI extension data.
fn parse_sni(bytes: &[u8], start: usize, end: usize) -> Option<String> {
    // 2 bytes: server_name_list_length
    if start + 2 > end {
        return None;
    }
    let mut pos = start + 2; // skip list length

    // Iterate entries looking for name_type 0x00 (hostname)
    while pos + 3 <= end {
        let name_type = bytes[pos];
        let name_len = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
        pos += 3;
        if pos + name_len > end {
            break;
        }
        if name_type == 0x00 {
            return Some(String::from_utf8_lossy(&bytes[pos..pos + name_len]).into_owned());
        }
        pos += name_len;
    }
    None
}

/// Parse ALPN extension for ClientHello: list of protocol names.
fn parse_alpn_client(bytes: &[u8], start: usize, end: usize) -> Vec<String> {
    let mut result = Vec::new();
    if start + 2 > end {
        return result;
    }
    let mut pos = start + 2; // skip protocol_name_list_length

    while pos < end {
        let proto_len = bytes[pos] as usize;
        pos += 1;
        if pos + proto_len > end {
            break;
        }
        result.push(String::from_utf8_lossy(&bytes[pos..pos + proto_len]).into_owned());
        pos += proto_len;
    }
    result
}

/// Parse ALPN extension for ServerHello: single selected protocol.
fn parse_alpn_server(bytes: &[u8], start: usize, end: usize) -> Option<String> {
    if start + 2 > end {
        return None;
    }
    let mut pos = start + 2; // skip protocol_name_list_length

    if pos + 1 > end {
        return None;
    }
    let proto_len = bytes[pos] as usize;
    pos += 1;
    if pos + proto_len > end {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[pos..pos + proto_len]).into_owned())
}

/// Parse supported_versions extension for ClientHello.
fn parse_supported_versions_client(bytes: &[u8], start: usize, end: usize) -> Vec<u16> {
    let mut result = Vec::new();
    if start + 1 > end {
        return result;
    }
    let list_len = bytes[start] as usize;
    let mut pos = start + 1;
    let list_end = (pos + list_len).min(end);

    while pos + 2 <= list_end {
        result.push(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
        pos += 2;
    }
    result
}

/// Parse signature_algorithms extension.
fn parse_sig_algs(bytes: &[u8], start: usize, end: usize) -> Vec<u16> {
    let mut result = Vec::new();
    if start + 2 > end {
        return result;
    }
    let alg_len = u16::from_be_bytes([bytes[start], bytes[start + 1]]) as usize;
    let mut pos = start + 2;
    let alg_end = (pos + alg_len).min(end);

    while pos + 2 <= alg_end {
        result.push(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
        pos += 2;
    }
    result
}

/// Parse key_share extension for ClientHello.
fn parse_key_share_client(bytes: &[u8], start: usize, end: usize) -> Vec<u16> {
    let mut result = Vec::new();
    if start + 2 > end {
        return result;
    }
    let _shares_len = u16::from_be_bytes([bytes[start], bytes[start + 1]]) as usize;
    let mut pos = start + 2;

    while pos + 4 <= end {
        let group = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let key_len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        pos += 4;
        if pos + key_len > end {
            break;
        }
        result.push(group);
        pos += key_len;
    }
    result
}
