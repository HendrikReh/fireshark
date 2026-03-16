use fireshark_core::DecodedFrame;

use crate::analysis::AnalyzedCapture;
use crate::model::{
    DecodeIssueEntryView, DecodeIssueView, EndpointCountView, LayerView, PacketDetailView,
    PacketSummaryView, ProtocolCountView, format_issue_kind,
};

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
) -> Vec<DecodeIssueEntryView> {
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
) -> Vec<PacketSummaryView> {
    filtered_packets(capture, search)
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

fn matches_filter(value: &str, filter: Option<&str>) -> bool {
    match filter {
        Some(filter) => value.eq_ignore_ascii_case(filter),
        None => true,
    }
}

impl PacketSummaryView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = packet.summary();

        Self {
            index,
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
            has_issues: !packet.packet().issues().is_empty(),
        }
    }
}

impl PacketDetailView {
    fn from_frame(index: usize, packet: &DecodedFrame) -> Self {
        let summary = PacketSummaryView::from_frame(index, packet);

        Self {
            index: summary.index,
            protocol: summary.protocol,
            source: summary.source,
            destination: summary.destination,
            length: summary.length,
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
