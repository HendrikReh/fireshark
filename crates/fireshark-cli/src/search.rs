//! Multi-criteria packet search with protocol, address, port, and text filters.

use std::path::Path;

use fireshark_core::{TrackingPipeline, format_utc};
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::json::PacketJson;
use crate::summary;

pub struct SearchCriteria<'a> {
    pub protocol: Option<&'a str>,
    pub source: Option<&'a str>,
    pub destination: Option<&'a str>,
    pub port: Option<u16>,
    pub text: Option<&'a str>,
    pub has_issues: bool,
    pub filter: Option<&'a str>,
}

pub fn run(
    path: &Path,
    criteria: &SearchCriteria<'_>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter_expr = criteria.filter.map(fireshark_filter::compile).transpose()?;

    let reader = CaptureReader::open(path)?;
    for (index, decoded) in TrackingPipeline::new(reader, decode_packet).enumerate() {
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", index + 1);
                continue;
            }
        };

        if let Some(ref expr) = filter_expr
            && !fireshark_filter::matches(expr, &decoded)
        {
            continue;
        }

        let pkt_summary = decoded.summary();
        let pkt_issues = decoded.packet().issues();

        if let Some(p) = criteria.protocol
            && !pkt_summary
                .protocol
                .to_ascii_lowercase()
                .contains(&p.to_ascii_lowercase())
        {
            continue;
        }
        if let Some(s) = criteria.source
            && !pkt_summary
                .source
                .to_ascii_lowercase()
                .contains(&s.to_ascii_lowercase())
        {
            continue;
        }
        if let Some(d) = criteria.destination
            && !pkt_summary
                .destination
                .to_ascii_lowercase()
                .contains(&d.to_ascii_lowercase())
        {
            continue;
        }
        if let Some(p) = criteria.port
            && !decoded
                .packet()
                .transport_ports()
                .is_some_and(|(src, dst)| src == p || dst == p)
        {
            continue;
        }
        if criteria.has_issues && pkt_issues.is_empty() {
            continue;
        }
        if let Some(t) = criteria.text {
            let t_lower = t.to_ascii_lowercase();
            let matches_text = pkt_summary.protocol.to_ascii_lowercase().contains(&t_lower)
                || pkt_summary.source.to_ascii_lowercase().contains(&t_lower)
                || pkt_summary
                    .destination
                    .to_ascii_lowercase()
                    .contains(&t_lower)
                || decoded
                    .packet()
                    .layer_names()
                    .iter()
                    .any(|n| n.to_ascii_lowercase().contains(&t_lower));
            if !matches_text {
                continue;
            }
        }

        if json {
            let ts = pkt_summary.timestamp.map(format_utc);
            let pkt = PacketJson {
                index: index + 1,
                timestamp: ts,
                protocol: pkt_summary.protocol,
                source: pkt_summary.source,
                destination: pkt_summary.destination,
                length: pkt_summary.length,
                stream_id: decoded.stream_id(),
            };
            println!("{}", serde_json::to_string(&pkt).unwrap());
        } else {
            let line = summary::format_line(
                index + 1,
                pkt_summary.timestamp,
                &pkt_summary.protocol,
                &pkt_summary.source,
                &pkt_summary.destination,
                pkt_summary.length,
            );
            println!("{}", color::colorize(&pkt_summary.protocol, &line));
        }
    }

    Ok(())
}
