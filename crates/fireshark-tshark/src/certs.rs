//! TLS certificate extraction via tshark field dissection.

use std::path::Path;
use std::process::Command;

use crate::reassembly::TlsCertInfo;

use crate::TsharkError;

/// Extract TLS certificate information from a capture file using tshark.
///
/// Runs tshark with a display filter for TLS Certificate handshake messages
/// and extracts subject/SAN fields via `-T fields`.
pub fn extract_certificates(
    tshark_path: &Path,
    capture_path: &Path,
) -> Result<Vec<TlsCertInfo>, TsharkError> {
    let output = Command::new(tshark_path)
        .arg("-r")
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
        .arg("separator=\t")
        .output()
        .map_err(|e| TsharkError::Execution(format!("failed to spawn tshark: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TsharkError::Execution(format!(
            "tshark exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

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

        let packet_index: usize = fields[0].parse().map_err(|e| {
            TsharkError::ParseOutput(format!("invalid frame number '{}': {e}", fields[0]))
        })?;

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
        let output = "42\texample.com\twww.example.com,example.com\tExample Inc.\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].packet_index, 42);
        assert_eq!(certs[0].common_name.as_deref(), Some("example.com"));
        assert_eq!(certs[0].san_dns_names, ["www.example.com", "example.com"]);
        assert_eq!(certs[0].organization.as_deref(), Some("Example Inc."));
    }

    #[test]
    fn parse_cert_tsv_empty_fields() {
        let output = "10\t\t\t\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].packet_index, 10);
        assert!(certs[0].common_name.is_none());
        assert!(certs[0].san_dns_names.is_empty());
        assert!(certs[0].organization.is_none());
    }

    #[test]
    fn parse_cert_tsv_multiple_rows() {
        let output = "5\tca.example.com\t\tCA Corp\n10\texample.com\twww.example.com\t\n";
        let certs = parse_cert_output(output).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].packet_index, 5);
        assert_eq!(certs[1].packet_index, 10);
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
