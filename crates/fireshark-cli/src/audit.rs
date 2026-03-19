//! Security audit output using the MCP audit engine.

use std::path::Path;

use colored::Colorize;
use fireshark_backend::{AnalyzedCapture, AuditEngine, VALID_PROFILES};

use crate::json::FindingJson;

pub fn run(
    path: &Path,
    max_packets: usize,
    json: bool,
    profile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(p) = profile
        && !VALID_PROFILES.contains(&p)
    {
        return Err(format!(
            "unknown audit profile '{p}'; valid profiles: {}",
            VALID_PROFILES.join(", ")
        )
        .into());
    }

    let capture = AnalyzedCapture::open_with_limit(path, max_packets)?;
    let findings = AuditEngine::audit_with_profile(&capture, profile);

    if json {
        for finding in &findings {
            let evidence_count: usize = finding
                .evidence
                .iter()
                .map(|e| e.packet_indexes.len())
                .sum();
            let f = FindingJson {
                id: finding.id.clone(),
                severity: finding.severity.clone(),
                category: finding.category.clone(),
                title: finding.title.clone(),
                evidence_count,
                escalated: finding.escalated,
                notes: finding.notes.clone(),
            };
            println!("{}", serde_json::to_string(&f).unwrap());
        }
        return Ok(());
    }

    println!("Security Audit");
    println!("{}", "\u{2500}".repeat(38));

    if findings.is_empty() {
        println!();
        println!("No findings.");
        return Ok(());
    }

    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;

    for finding in &findings {
        println!();

        let severity_upper = finding.severity.to_uppercase();
        let severity_label = match severity_upper.as_str() {
            "HIGH" => format!("[{}]", severity_upper).red().to_string(),
            "MEDIUM" => format!("[{}]", severity_upper).yellow().to_string(),
            _ => format!("[{}]", severity_upper),
        };

        match severity_upper.as_str() {
            "HIGH" => high_count += 1,
            "MEDIUM" => medium_count += 1,
            "LOW" => low_count += 1,
            other => {
                eprintln!("warning: unrecognized severity {other:?}, counting as low");
                low_count += 1;
            }
        }

        let escalated_label = if finding.escalated {
            " [ESCALATED]".to_string()
        } else {
            String::new()
        };
        println!("{severity_label}{escalated_label} {}", finding.title);
        println!("  {}", finding.summary);

        if let Some(notes) = &finding.notes {
            println!("  Notes: {notes}");
        }

        for evidence in &finding.evidence {
            println!("  Evidence: {} packets", evidence.packet_indexes.len());
        }
    }

    println!();

    let mut parts = Vec::new();
    if high_count > 0 {
        parts.push(format!("{high_count} high"));
    }
    if medium_count > 0 {
        parts.push(format!("{medium_count} medium"));
    }
    if low_count > 0 {
        parts.push(format!("{low_count} low"));
    }

    println!("{} findings ({})", findings.len(), parts.join(", "));

    Ok(())
}
