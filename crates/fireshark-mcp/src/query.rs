use fireshark_core::DecodedFrame;

use crate::analysis::AnalyzedCapture;
use crate::filter::matches_filter;
use crate::model::{
    DecodeIssueEntryView, DecodeIssueView, EndpointCountView, LayerView, PacketDetailView,
    PacketSummaryView, ProtocolCountView, format_issue_kind,
};

pub const MAX_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Clone, Default)]
pub struct PacketSearch<'a> {
    pub protocol: Option<&'a str>,
    pub source: Option<&'a str>,
    pub destination: Option<&'a str>,
    pub port: Option<u16>,
    pub text: Option<&'a str>,
    pub has_issues: Option<bool>,
}

pub fn list_packets(
    capture: &AnalyzedCapture,
    offset: usize,
    limit: usize,
    protocol: Option<&str>,
    has_issues: Option<bool>,
) -> Vec<PacketSummaryView> {
    let search = PacketSearch {
        protocol,
        has_issues,
        ..PacketSearch::default()
    };
    let limit = clamp_limit(limit);

    filtered_packets(capture, &search)
        .skip(offset)
        .take(limit)
        .map(|(index, packet)| PacketSummaryView::from_frame(index, packet))
        .collect()
}

pub fn get_packet(capture: &AnalyzedCapture, index: usize) -> Option<PacketDetailView> {
    capture
        .packets()
        .get(index)
        .map(|packet| PacketDetailView::from_frame(index, packet))
}

pub fn list_decode_issues(
    capture: &AnalyzedCapture,
    kind: Option<&str>,
    offset: usize,
    limit: usize,
) -> Vec<DecodeIssueEntryView> {
    let limit = clamp_limit(limit);

    capture
        .packets()
        .iter()
        .enumerate()
        .flat_map(|(packet_index, packet)| {
            packet.packet().issues().iter().filter_map(move |issue| {
                let issue_kind = format_issue_kind(issue.kind());
                if matches_filter(&issue_kind, kind) {
                    Some(DecodeIssueEntryView {
                        packet_index,
                        kind: issue_kind,
                        offset: issue.offset(),
                    })
                } else {
                    None
                }
            })
        })
        .skip(offset)
        .take(limit)
        .collect()
}

pub fn summarize_protocols(capture: &AnalyzedCapture) -> Vec<ProtocolCountView> {
    let mut protocols = capture
        .protocol_counts()
        .iter()
        .map(|(protocol, packet_count)| ProtocolCountView {
            protocol: protocol.clone(),
            packet_count: *packet_count,
        })
        .collect::<Vec<_>>();

    protocols.sort_by(|left, right| {
        right
            .packet_count
            .cmp(&left.packet_count)
            .then_with(|| left.protocol.cmp(&right.protocol))
    });

    protocols
}

pub fn top_endpoints(capture: &AnalyzedCapture, limit: usize) -> Vec<EndpointCountView> {
    let limit = clamp_limit(limit);
    let mut endpoints = capture
        .endpoint_counts()
        .iter()
        .map(|(endpoint, packet_count)| EndpointCountView {
            endpoint: endpoint.clone(),
            packet_count: *packet_count,
        })
        .collect::<Vec<_>>();

    endpoints.sort_by(|left, right| {
        right
            .packet_count
            .cmp(&left.packet_count)
            .then_with(|| left.endpoint.cmp(&right.endpoint))
    });
    endpoints.truncate(limit);
    endpoints
}

pub fn search_packets(
    capture: &AnalyzedCapture,
    search: &PacketSearch<'_>,
    offset: usize,
    limit: usize,
) -> Vec<PacketSummaryView> {
    let limit = clamp_limit(limit);

    filtered_packets(capture, search)
        .skip(offset)
        .take(limit)
        .map(|(index, packet)| PacketSummaryView::from_frame(index, packet))
        .collect()
}

fn filtered_packets<'a>(
    capture: &'a AnalyzedCapture,
    search: &'a PacketSearch<'_>,
) -> impl Iterator<Item = (usize, &'a DecodedFrame)> + 'a {
    capture
        .packets()
        .iter()
        .enumerate()
        .filter(move |(_, packet)| matches_search(packet, search))
}

fn clamp_limit(limit: usize) -> usize {
    limit.min(MAX_PAGE_SIZE)
}

fn matches_search(packet: &DecodedFrame, search: &PacketSearch<'_>) -> bool {
    let summary = packet.summary();
    let has_issues = !packet.packet().issues().is_empty();

    if !matches_filter(&summary.protocol, search.protocol) {
        return false;
    }

    if !matches_filter(&summary.source, search.source) {
        return false;
    }

    if !matches_filter(&summary.destination, search.destination) {
        return false;
    }

    if let Some(expected) = search.has_issues
        && has_issues != expected
    {
        return false;
    }

    if let Some(port) = search.port {
        match packet.packet().transport_ports() {
            Some((source_port, destination_port))
                if source_port == port || destination_port == port => {}
            _ => return false,
        }
    }

    if let Some(text) = search.text {
        let needle = text.to_ascii_lowercase();
        let haystacks = [
            summary.protocol,
            summary.source,
            summary.destination,
            packet.packet().layer_names().join(" "),
        ];

        if !haystacks
            .into_iter()
            .any(|value| value.to_ascii_lowercase().contains(&needle))
        {
            return false;
        }
    }

    true
}

impl PacketSummaryView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = packet.summary();

        Self {
            index,
            timestamp: packet.frame().timestamp().map(format_timestamp),
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
            original_len: packet.frame().original_len(),
            has_issues: !packet.packet().issues().is_empty(),
        }
    }
}

impl PacketDetailView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = PacketSummaryView::from_frame(index, packet);

        Self {
            index: summary.index,
            timestamp: summary.timestamp,
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
            original_len: summary.original_len,
            has_issues: summary.has_issues,
            layers: packet
                .packet()
                .layers()
                .iter()
                .map(LayerView::from_layer)
                .collect(),
            issues: packet
                .packet()
                .issues()
                .iter()
                .map(DecodeIssueView::from_issue)
                .collect(),
        }
    }
}

fn format_timestamp(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let day_secs = total_secs % 86_400;
    let hour = day_secs / 3_600;
    let minute = (day_secs % 3_600) / 60;
    let second = day_secs % 60;
    let (year, month, day) = civil_from_days((total_secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant's civil_from_days algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
