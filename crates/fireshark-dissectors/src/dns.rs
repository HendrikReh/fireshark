use std::net::{Ipv4Addr, Ipv6Addr};

use fireshark_core::{DnsAnswer, DnsAnswerData, DnsLayer, Layer};

use crate::DecodeError;

pub const UDP_PORT: u16 = 53;
const HEADER_LEN: usize = 12;

/// Maximum number of labels to prevent malicious deeply nested names.
const MAX_LABELS: usize = 128;

/// Maximum total name length per RFC 1035.
const MAX_NAME_LEN: usize = 255;

pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "DNS",
            offset: offset + bytes.len(),
        });
    }

    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let question_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    // authority_count and additional_count read but not stored
    let _authority_count = u16::from_be_bytes([bytes[8], bytes[9]]);
    let _additional_count = u16::from_be_bytes([bytes[10], bytes[11]]);

    // Attempt to parse the first question entry
    let (query_name, query_type, question_end) = if question_count > 0 {
        parse_question(bytes)
    } else {
        (None, None, HEADER_LEN)
    };

    let answers = if is_response && answer_count > 0 {
        parse_answers(bytes, question_end, answer_count)
    } else {
        Vec::new()
    };

    Ok(Layer::Dns(DnsLayer {
        transaction_id,
        is_response,
        opcode,
        question_count,
        answer_count,
        query_name,
        query_type,
        answers,
    }))
}

/// Parse the first question entry from the DNS message.
/// Returns (query_name, query_type, end_offset) — the third element is the byte offset
/// where the question section ends, so answer parsing knows where to start.
fn parse_question(bytes: &[u8]) -> (Option<String>, Option<u16>, usize) {
    let Some((name, consumed)) = parse_name(bytes, HEADER_LEN) else {
        return (None, None, HEADER_LEN);
    };

    let qtype_start = HEADER_LEN + consumed;
    let query_name = if name.is_empty() { None } else { Some(name) };
    // Need 4 bytes for qtype (2) + qclass (2)
    if qtype_start + 4 > bytes.len() {
        return (query_name, None, qtype_start);
    }

    let query_type = u16::from_be_bytes([bytes[qtype_start], bytes[qtype_start + 1]]);
    // qclass read but not stored
    let _query_class = u16::from_be_bytes([bytes[qtype_start + 2], bytes[qtype_start + 3]]);

    let question_end = qtype_start + 4;
    (query_name, Some(query_type), question_end)
}

/// Maximum number of answer records to parse (guards against malicious packets).
const MAX_ANSWERS: u16 = 100;

/// Parse answer records from the DNS message.
///
/// Returns a `Vec<DnsAnswer>` with up to `min(count, MAX_ANSWERS)` entries.
/// Stops early if any record is truncated.
fn parse_answers(bytes: &[u8], start: usize, count: u16) -> Vec<DnsAnswer> {
    let limit = count.min(MAX_ANSWERS) as usize;
    let mut answers = Vec::with_capacity(limit);
    let mut pos = start;

    for _ in 0..limit {
        // Parse the answer name (usually a compression pointer)
        let Some((name, name_consumed)) = parse_name(bytes, pos) else {
            break;
        };
        pos += name_consumed;

        // Need 10 bytes: type(2) + class(2) + TTL(4) + rdlength(2)
        if pos + 10 > bytes.len() {
            break;
        }

        let record_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        // class read but not stored
        let _class = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
        let ttl = u32::from_be_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > bytes.len() {
            break;
        }

        let data = match record_type {
            1 if rdlength == 4 => DnsAnswerData::A(Ipv4Addr::new(
                bytes[pos],
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
            )),
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[pos..pos + 16]);
                DnsAnswerData::Aaaa(Ipv6Addr::from(octets))
            }
            _ => DnsAnswerData::Other(bytes[pos..pos + rdlength].to_vec()),
        };

        pos += rdlength;

        answers.push(DnsAnswer {
            name,
            record_type,
            ttl,
            data,
        });
    }

    answers
}

/// Parse a DNS name using label-length encoding.
///
/// Returns `Some((name, bytes_consumed))` on success, `None` on failure.
/// `bytes_consumed` counts bytes from `start` through the terminating zero
/// (or up to a compression pointer, which terminates parsing).
fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut total_len: usize = 0;

    for _ in 0..MAX_LABELS {
        if pos >= bytes.len() {
            return None;
        }

        let n = bytes[pos];

        if n == 0 {
            // End of name
            let consumed = pos - start + 1; // +1 for the zero byte
            let name = labels.join(".");
            return Some((name, consumed));
        }

        if n & 0xC0 == 0xC0 {
            // Compression pointer — stop parsing, return what we have
            // (don't follow pointers in v1)
            if pos + 1 >= bytes.len() {
                return None; // pointer byte missing
            }
            let name = labels.join(".");
            // If nothing was accumulated before the pointer, return empty
            // which the caller converts to None
            let consumed = pos - start + 2; // pointer is 2 bytes
            return Some((name, consumed));
        }

        if n > 63 {
            // Invalid label length
            return None;
        }

        let label_len = n as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;

        if label_end > bytes.len() {
            return None; // truncated
        }

        total_len += label_len + 1; // +1 for the length byte (or dot separator)
        if total_len > MAX_NAME_LEN {
            return None;
        }

        let label = String::from_utf8_lossy(&bytes[label_start..label_end]).into_owned();
        labels.push(label);
        pos = label_end;
    }

    // Exceeded max labels
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_simple() {
        // "example.com" = 07 "example" 03 "com" 00
        let data = b"\x07example\x03com\x00";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 13); // 1+7+1+3+1
    }

    #[test]
    fn parse_name_with_compression_pointer() {
        // "www" then compression pointer 0xC00C
        let data = b"\x03www\xC0\x0C";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "www");
        assert_eq!(consumed, 6); // 1+3+2
    }

    #[test]
    fn parse_name_only_pointer_yields_empty() {
        let data = b"\xC0\x0C";
        let (name, consumed) = parse_name(data, 0).unwrap();
        assert_eq!(name, "");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_name_truncated_returns_none() {
        let data = b"\x07exam"; // says 7 bytes but only 4
        assert!(parse_name(data, 0).is_none());
    }

    #[test]
    fn parse_name_invalid_label_length() {
        let data = b"\x80invalid"; // 0x80 has top bit set but not both top bits
        assert!(parse_name(data, 0).is_none());
    }
}
