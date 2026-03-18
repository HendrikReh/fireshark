//! Security audit output using the MCP audit engine.

use std::path::Path;

use colored::Colorize;
use fireshark_mcp::analysis::AnalyzedCapture;
use fireshark_mcp::audit::AuditEngine;

use crate::json::FindingJson;

pub fn run(path: &Path, max_packets: usize, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let capture = AnalyzedCapture::open_with_limit(path, max_packets)?;
    let findings = AuditEngine::audit(&capture);

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

        println!("{severity_label} {}", finding.title);
        println!("  {}", finding.summary);

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
