use std::net::{Ipv4Addr, Ipv6Addr};

use fireshark_core::{DecodeIssue, DnsAnswer, DnsAnswerData, DnsLayer, Layer};

use crate::DecodeError;

pub const UDP_PORT: u16 = 53;
const HEADER_LEN: usize = 12;

/// Maximum number of labels to prevent malicious deeply nested names.
const MAX_LABELS: usize = 128;

/// Maximum total name length per RFC 1035.
const MAX_NAME_LEN: usize = 255;

pub fn parse(bytes: &[u8], offset: usize) -> Result<(Layer, Vec<DecodeIssue>), DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            layer: "DNS",
            offset: offset + bytes.len(),
        });
    }

    let mut issues = Vec::new();

    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x000F) as u8;
    let question_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    // authority_count and additional_count read but not stored
    let _authority_count = u16::from_be_bytes([bytes[8], bytes[9]]);
    let _additional_count = u16::from_be_bytes([bytes[10], bytes[11]]);

    // Parse question entries, advancing past each one so answer parsing
    // knows where to start. Extract query_name/query_type from the first
    // question only; remaining questions are skipped but consumed.
    let max_questions = (question_count as usize).min(10);
    let mut truncated_body = false;
    let (query_name, query_type, question_end) = if max_questions > 0 {
        let (name, qtype, mut end) = parse_question(bytes, HEADER_LEN);
        if name.is_none() && question_count > 0 {
            truncated_body = true;
        }
        for _ in 1..max_questions {
            let (_, _, next_end) = parse_question(bytes, end);
            if next_end == end {
                truncated_body = true;
                break; // could not advance; avoid infinite loop
            }
            end = next_end;
        }
        (name, qtype, end)
    } else {
        (None, None, HEADER_LEN)
    };

    let answers = if is_response && answer_count > 0 {
        let parsed = parse_answers(bytes, question_end, answer_count);
        if (parsed.len() as u16) < answer_count.min(MAX_ANSWERS) {
            truncated_body = true;
        }
        parsed
    } else {
        Vec::new()
    };

    if truncated_body {
        issues.push(DecodeIssue::truncated(offset + bytes.len()));
    }

    Ok((
        Layer::Dns(DnsLayer {
            transaction_id,
            is_response,
            opcode,
            rcode,
            question_count,
            answer_count,
            query_name,
            query_type,
            answers,
        }),
        issues,
    ))
}

/// Parse a question entry from the DNS message starting at `start`.
/// Returns (query_name, query_type, end_offset) — the third element is the byte offset
/// where this question entry ends, so the next question (or answer parsing) knows where to start.
fn parse_question(bytes: &[u8], start: usize) -> (Option<String>, Option<u16>, usize) {
    let Some((name, consumed)) = parse_name(bytes, start) else {
        return (None, None, start);
    };

    let qtype_start = start + consumed;
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

/// Maximum number of compression pointer hops to prevent infinite loops.
const MAX_POINTER_HOPS: usize = 16;

/// Parse a DNS name using label-length encoding with compression pointer
/// following per RFC 1035 §4.1.4.
///
/// Returns `Some((name, bytes_consumed))` on success, `None` on failure.
/// `bytes_consumed` counts bytes from `start` through the terminating zero
/// or the first compression pointer encountered in the original position
/// (not the target — RFC 1035 says the pointer terminates the name in the
/// original stream).
fn parse_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut total_len: usize = 0;
    // Track bytes consumed in the original stream (before any pointer jump).
    let mut consumed: Option<usize> = None;
    let mut pointer_hops = 0;

    for _ in 0..MAX_LABELS {
        if pos >= bytes.len() {
            return None;
        }

        let n = bytes[pos];

        if n == 0 {
            // End of name. Use pre-recorded consumed bytes if we followed a
            // pointer (pos may be in a different part of the buffer).
            let c = consumed.unwrap_or_else(|| pos - start + 1);
            let name = labels.join(".");
            return Some((name, c));
        }

        if n & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= bytes.len() {
                return None;
            }
            // Record consumed bytes only on the first pointer (original stream position).
            if consumed.is_none() {
                consumed = Some(pos - start + 2);
            }
            pointer_hops += 1;
            if pointer_hops > MAX_POINTER_HOPS {
                return None; // too many hops — likely a loop
            }
            let offset = (usize::from(n & 0x3F) << 8) | usize::from(bytes[pos + 1]);
            if offset >= bytes.len() {
                return None;
            }
            pos = offset;
            continue;
        }

        if n > 63 {
            return None;
        }

        let label_len = n as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;

        if label_end > bytes.len() {
            return None;
        }

        total_len += label_len + 1;
        if total_len > MAX_NAME_LEN {
            return None;
        }

        let label = String::from_utf8_lossy(&bytes[label_start..label_end]).into_owned();
        labels.push(label);
        pos = label_end;
    }

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
    fn parse_name_follows_compression_pointer() {
        // Layout: "example.com" at offset 0, then "www" + pointer to offset 0
        // Offset 0: 07 "example" 03 "com" 00  (13 bytes)
        // Offset 13: 03 "www" C0 00            (6 bytes — pointer to offset 0)
        let mut data = Vec::new();
        data.extend_from_slice(b"\x07example\x03com\x00"); // offset 0..13
        data.extend_from_slice(b"\x03www\xC0\x00"); // offset 13..19
        let (name, consumed) = parse_name(&data, 13).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(consumed, 6); // 1+3+2 (pointer terminates original stream)
    }

    #[test]
    fn parse_name_pointer_only_resolves_target() {
        // Layout: "example.com" at offset 0, then pointer to offset 0
        let mut data = Vec::new();
        data.extend_from_slice(b"\x07example\x03com\x00"); // offset 0..13
        data.extend_from_slice(b"\xC0\x00"); // offset 13..15
        let (name, consumed) = parse_name(&data, 13).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_name_pointer_loop_rejected() {
        // Self-referencing pointer at offset 0
        let data = b"\xC0\x00";
        // Should be rejected by MAX_POINTER_HOPS
        assert!(parse_name(data, 0).is_none());
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

    #[test]
    fn parse_multiple_questions() {
        // Build a DNS packet with 2 questions:
        //   Q1: "a.example" type A (1) class IN (1)
        //   Q2: "b.example" type AAAA (28) class IN (1)
        let mut data = Vec::new();
        // Header: txid=0x0001, flags=0x0000 (query), qdcount=2, ancount=0, nscount=0, arcount=0
        data.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Q1 name: 01 "a" 07 "example" 00
        data.extend_from_slice(b"\x01a\x07example\x00");
        // Q1 qtype=1 (A), qclass=1 (IN)
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Q2 name: 01 "b" 07 "example" 00
        data.extend_from_slice(b"\x01b\x07example\x00");
        // Q2 qtype=28 (AAAA), qclass=1 (IN)
        data.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]);

        let (layer, issues) = parse(&data, 0).unwrap();
        match layer {
            Layer::Dns(dns) => {
                assert_eq!(dns.question_count, 2);
                // First question's name and type are extracted
                assert_eq!(dns.query_name.as_deref(), Some("a.example"));
                assert_eq!(dns.query_type, Some(1));
            }
            other => panic!("expected DNS layer, got: {other:?}"),
        }
        assert!(issues.is_empty(), "complete packet should have no issues");
    }

    #[test]
    fn truncated_question_reports_issue() {
        // Header claims 1 question but body is truncated
        let data: Vec<u8> = vec![
            0x00, 0x01, // txid
            0x00, 0x00, // flags (query)
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x00, // nscount=0
            0x00, 0x00, // arcount=0
            0x07, // label length=7 but only 2 bytes follow
            b'e', b'x',
        ];
        let (layer, issues) = parse(&data, 42).unwrap();
        match layer {
            Layer::Dns(dns) => {
                assert_eq!(dns.question_count, 1);
                assert!(dns.query_name.is_none());
            }
            other => panic!("expected DNS layer, got: {other:?}"),
        }
        assert!(
            !issues.is_empty(),
            "truncated question should produce an issue"
        );
    }
}
