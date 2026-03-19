//! TLS certificate extraction via tshark field dissection.

use std::path::Path;
use std::process::Command;

use crate::command::{DEFAULT_TIMEOUT, run_with_timeout};
use crate::reassembly::TlsCertInfo;

use crate::TsharkError;

/// Extract TLS certificate information from a capture file using tshark.
///
/// Runs tshark with a display filter for TLS Certificate handshake messages
/// and extracts subject/SAN fields via `-T fields`.
///
/// Paths are passed via `Command::arg` (no shell), so injection is not possible.
pub fn extract_certificates(
    tshark_path: &Path,
    capture_path: &Path,
) -> Result<Vec<TlsCertInfo>, TsharkError> {
    let mut cmd = Command::new(tshark_path);
    cmd.arg("-r")
        .arg(capture_path)
        .arg("-Y")
        .arg("tls.handshake.type == 11")
        .arg("-T")
        .arg("fields")
        .arg("-e")
        .arg("frame.number")
        .arg("-e")
        .arg("x509sat.printableString")
        .arg("-e")
        .arg("x509ce.dNSName")
        .arg("-e")
        .arg("x509sat.OrganizationName")
        .arg("-E")
        .arg("separator=\t");

    let output = run_with_timeout(cmd, DEFAULT_TIMEOUT)?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| TsharkError::ParseOutput(format!("tshark output is not valid UTF-8: {e}")))?;

    parse_cert_output(&stdout)
}

/// Parse the TSV output from tshark certificate field extraction.
///
/// Each line contains tab-separated fields:
/// `frame.number \t x509sat.printableString \t x509ce.dNSName \t x509sat.OrganizationName`
///
/// Multiple values within a field are comma-separated by tshark.
pub fn parse_cert_output(output: &str) -> Result<Vec<TlsCertInfo>, TsharkError> {
    let mut certs = Vec::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.is_empty() {
            continue;
        }

        let frame_number: usize = fields[0].parse().map_err(|e| {
            TsharkError::ParseOutput(format!("invalid frame number '{}': {e}", fields[0]))
        })?;
        // tshark frame.number is 1-based; convert to 0-based for consistency
        // with the rest of the fireshark API.
        let packet_index = frame_number.saturating_sub(1);

        let common_name = fields.get(1).and_then(|s| non_empty(s)).map(String::from);

        let san_dns_names: Vec<String> = fields
            .get(2)
            .and_then(|s| non_empty(s))
            .map(|s| s.split(',').map(|n| n.trim().to_string()).collect())
            .unwrap_or_default();

        let organization = fields.get(3).and_then(|s| non_empty(s)).map(String::from);

        certs.push(TlsCertInfo {
            packet_index,
            common_name,
            san_dns_names,
            organization,
        });
    }

    Ok(certs)
}

fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cert_tsv_single_row() {
        // tshark frame.number is 1-based; packet_index should be 0-based (42 - 1 = 41)
        let output = "42\texample.com\twww.example.com,example.com\tExample Inc.\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].packet_index, 41);
        assert_eq!(certs[0].common_name.as_deref(), Some("example.com"));
        assert_eq!(certs[0].san_dns_names, ["www.example.com", "example.com"]);
        assert_eq!(certs[0].organization.as_deref(), Some("Example Inc."));
    }

    #[test]
    fn parse_cert_tsv_first_packet_is_zero_based() {
        // frame.number=1 should map to packet_index=0
        let output = "1\texample.com\t\t\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs[0].packet_index, 0);
    }

    #[test]
    fn parse_cert_tsv_empty_fields() {
        let output = "10\t\t\t\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].packet_index, 9); // 10 - 1
        assert!(certs[0].common_name.is_none());
        assert!(certs[0].san_dns_names.is_empty());
        assert!(certs[0].organization.is_none());
    }

    #[test]
    fn parse_cert_tsv_multiple_rows() {
        let output = "5\tca.example.com\t\tCA Corp\n10\texample.com\twww.example.com\t\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].packet_index, 4); // 5 - 1
        assert_eq!(certs[1].packet_index, 9); // 10 - 1
    }

    #[test]
    fn parse_cert_tsv_empty_output() {
        let certs = parse_cert_output("").unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn parse_cert_tsv_bad_frame_number() {
        let output = "notanumber\texample.com\t\t\n";
        assert!(parse_cert_output(output).is_err());
    }
}
