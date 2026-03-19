//! TLS certificate extraction via tshark.

use std::path::Path;

use serde::Serialize;

pub fn run(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (tshark_path, _version) = fireshark_tshark::discover()
        .map_err(|e| format!("tshark required for certificate extraction: {e}"))?;

    let certs = fireshark_tshark::certs::extract_certificates(&tshark_path, path)?;

    if certs.is_empty() {
        if !json {
            println!("No TLS certificates found.");
        }
        return Ok(());
    }

    if json {
        for cert in &certs {
            let c = CertJson {
                packet_index: cert.packet_index,
                common_name: cert.common_name.as_deref(),
                san_dns_names: &cert.san_dns_names,
                organization: cert.organization.as_deref(),
            };
            println!("{}", serde_json::to_string(&c).unwrap());
        }
    } else {
        println!("TLS Certificates");
        println!("{}", "\u{2500}".repeat(38));

        for cert in &certs {
            println!();
            println!(
                "  Packet {}",
                cert.packet_index + 1 // display as 1-indexed
            );
            if let Some(cn) = &cert.common_name {
                println!("    CN:  {cn}");
            }
            if !cert.san_dns_names.is_empty() {
                println!("    SAN: {}", cert.san_dns_names.join(", "));
            }
            if let Some(org) = &cert.organization {
                println!("    Org: {org}");
            }
        }

        println!();
        println!("{} certificate(s)", certs.len());
    }

    Ok(())
}

#[derive(Serialize)]
struct CertJson<'a> {
    packet_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_name: Option<&'a str>,
    san_dns_names: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<&'a str>,
}
