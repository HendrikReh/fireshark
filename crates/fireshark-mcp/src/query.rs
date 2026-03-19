use fireshark_core::DecodedFrame;
use fireshark_filter::CompiledFilter;

use crate::filter::matches_filter;
use crate::model::{
    DecodeIssueEntryView, DecodeIssueView, EndpointCountView, LayerView, PacketDetailView,
    PacketSummaryView, ProtocolCountView, StreamView, format_issue_kind,
};
use fireshark_backend::AnalyzedCapture;

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
    filter: Option<&CompiledFilter>,
) -> Vec<PacketSummaryView> {
    let search = PacketSearch {
        protocol,
        has_issues,
        ..PacketSearch::default()
    };
    let limit = clamp_limit(limit);

    filtered_packets(capture, &search, filter)
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

pub fn list_streams(capture: &AnalyzedCapture, offset: usize, limit: usize) -> Vec<StreamView> {
    let limit = clamp_limit(limit);

    capture
        .streams()
        .iter()
        .skip(offset)
        .take(limit)
        .map(StreamView::from_metadata)
        .collect()
}

pub fn get_stream(
    capture: &AnalyzedCapture,
    stream_id: u32,
) -> Option<(StreamView, Vec<PacketSummaryView>)> {
    let meta = capture.tracker().get(stream_id)?;
    let stream_view = StreamView::from_metadata(meta);
    let packets = capture
        .stream_packets(stream_id)
        .into_iter()
        .map(|(index, pkt)| PacketSummaryView::from_frame(index, pkt))
        .collect();
    Some((stream_view, packets))
}

pub fn search_packets(
    capture: &AnalyzedCapture,
    search: &PacketSearch<'_>,
    offset: usize,
    limit: usize,
    filter: Option<&CompiledFilter>,
) -> Vec<PacketSummaryView> {
    let limit = clamp_limit(limit);

    filtered_packets(capture, search, filter)
        .skip(offset)
        .take(limit)
        .map(|(index, packet)| PacketSummaryView::from_frame(index, packet))
        .collect()
}

fn filtered_packets<'a>(
    capture: &'a AnalyzedCapture,
    search: &'a PacketSearch<'_>,
    filter: Option<&'a CompiledFilter>,
) -> impl Iterator<Item = (usize, &'a DecodedFrame)> + 'a {
    capture
        .packets()
        .iter()
        .enumerate()
        .filter(move |(_, packet)| {
            if !matches_search(packet, search) {
                return false;
            }
            if let Some(expr) = filter
                && !fireshark_filter::matches(expr, packet)
            {
                return false;
            }
            true
        })
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
        let summary_match = [&summary.protocol, &summary.source, &summary.destination]
            .iter()
            .any(|v| v.to_ascii_lowercase().contains(&needle));
        if !summary_match {
            let layer_match = packet
                .packet()
                .layers()
                .iter()
                .any(|l| l.name().to_ascii_lowercase().contains(&needle));
            if !layer_match {
                return false;
            }
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

pub(crate) use fireshark_core::format_utc as format_timestamp;
