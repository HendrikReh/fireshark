use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use thiserror::Error;

use crate::analysis::{AnalyzedCapture, DEFAULT_MAX_PACKETS};
use crate::audit::{AuditEngine, VALID_PROFILES};
use crate::filter::matches_filter;
use crate::model::{
    CaptureComparisonView, CaptureDescriptionView, CaptureSummaryView, CloseCaptureResponse,
    DecodeIssueEntryView, EndpointCountView, FindingView, HostDiffView, OpenCaptureResponse,
    PacketDetailView, PacketSummaryView, PortDiffView, ProtocolCountView, ProtocolDiffView,
    StreamView,
};
use crate::query::{
    PacketSearch, format_timestamp, get_packet, get_stream, list_decode_issues, list_packets,
    list_streams, search_packets, summarize_protocols, top_endpoints,
};
use crate::session::{SessionError, SessionManager};

const DEFAULT_MAX_SESSIONS: usize = 8;

/// Lightweight snapshot of session metadata for reassembly operations.
pub struct SessionSnapshot {
    path: Option<PathBuf>,
}

impl SessionSnapshot {
    /// The capture file path, if available.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("packet {index} was not found in session {session_id}")]
    PacketNotFound { session_id: String, index: usize },

    #[error("finding {finding_id} was not found in session {session_id}")]
    FindingNotFound {
        session_id: String,
        finding_id: String,
    },

    #[error("stream {stream_id} was not found in session {session_id}")]
    StreamNotFound { session_id: String, stream_id: u32 },

    #[error("unknown audit profile '{profile}'; valid profiles: {valid}")]
    InvalidProfile { profile: String, valid: String },
}

#[derive(Clone)]
pub struct ToolService {
    sessions: Arc<Mutex<SessionManager>>,
}

impl ToolService {
    pub fn new_default() -> Self {
        Self::new(SessionManager::new(DEFAULT_MAX_SESSIONS))
    }

    pub fn new(sessions: SessionManager) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(sessions)),
        }
    }

    // ── helpers ───────────────────────────────────────────────────────

    /// Acquire the lock, touch the session, and return an `Arc` to its
    /// capture. The lock is released as soon as this function returns.
    async fn acquire_capture(&self, session_id: &str) -> Result<Arc<AnalyzedCapture>, ToolError> {
        let mut sessions = self.sessions.lock().await;
        sessions.expire_idle();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
        session.touch();
        Ok(session.capture_arc())
    }

    // ── open / close ─────────────────────────────────────────────────

    /// Open a capture file and create a new analysis session.
    ///
    /// **Path security note (v1):** No path restriction or sandboxing is applied;
    /// the caller is responsible for validating that `path` points to a trusted
    /// capture file. This is a known limitation documented for the current
    /// release.
    pub async fn open_capture(
        &self,
        path: impl AsRef<Path>,
        max_packets: Option<usize>,
    ) -> Result<OpenCaptureResponse, ToolError> {
        let limit = max_packets.unwrap_or(DEFAULT_MAX_PACKETS).min(1_000_000);
        let capture_path = path.as_ref().to_path_buf();

        // 1. Quick check: expire idle sessions first, then verify room.
        {
            let mut sessions = self.sessions.lock().await;
            sessions.expire_idle();
            sessions.check_limit()?;
        }
        // Lock released here.

        // 2. Expensive I/O — no lock held.
        let capture = AnalyzedCapture::open_with_limit(&path, limit)
            .map_err(|e| ToolError::Session(SessionError::Analysis(e)))?;

        // 3. Re-acquire lock, expire again (time may have passed), and
        //    recheck the limit to prevent concurrent opens from exceeding
        //    max_sessions.
        let mut sessions = self.sessions.lock().await;
        sessions.expire_idle();
        sessions.check_limit()?;
        let session_id = sessions.insert_with_path(capture, capture_path);

        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.touch();
        Ok(open_capture_response(session.capture(), &session.id))
    }

    pub async fn close_capture(&self, session_id: &str) -> Result<CloseCaptureResponse, ToolError> {
        let mut sessions = self.sessions.lock().await;
        sessions.close(session_id)?;

        Ok(CloseCaptureResponse {
            session_id: session_id.to_string(),
            closed: true,
        })
    }

    /// Acquire the session path for reassembly operations (tshark follow, certs).
    pub async fn acquire_capture_for_reassembly(
        &self,
        session_id: &str,
    ) -> Result<SessionSnapshot, ToolError> {
        let mut sessions = self.sessions.lock().await;
        sessions.expire_idle();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
        session.touch();
        Ok(SessionSnapshot {
            path: session.path().map(|p| p.to_path_buf()),
        })
    }

    // ── read-only tools (use Arc, release lock early) ────────────────

    pub async fn describe_capture(
        &self,
        session_id: &str,
    ) -> Result<CaptureDescriptionView, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(CaptureDescriptionView {
            session_id: session_id.to_string(),
            packet_count: capture.packet_count(),
            decode_issue_count: decode_issue_count(&capture),
            protocol_counts: summarize_protocols(&capture),
            top_endpoints: top_endpoints(&capture, 10),
        })
    }

    pub async fn list_packets(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
        protocol: Option<&str>,
        has_issues: Option<bool>,
        filter: Option<&fireshark_filter::CompiledFilter>,
    ) -> Result<Vec<PacketSummaryView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(list_packets(
            &capture, offset, limit, protocol, has_issues, filter,
        ))
    }

    pub async fn get_packet(
        &self,
        session_id: &str,
        index: usize,
    ) -> Result<PacketDetailView, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        get_packet(&capture, index).ok_or_else(|| ToolError::PacketNotFound {
            session_id: session_id.to_string(),
            index,
        })
    }

    pub async fn list_decode_issues(
        &self,
        session_id: &str,
        kind: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DecodeIssueEntryView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(list_decode_issues(&capture, kind, offset, limit))
    }

    pub async fn summarize_protocols(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtocolCountView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(summarize_protocols(&capture))
    }

    pub async fn top_endpoints(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<EndpointCountView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(top_endpoints(&capture, limit))
    }

    pub async fn search_packets(
        &self,
        session_id: &str,
        search: &PacketSearch<'_>,
        offset: usize,
        limit: usize,
        filter: Option<&fireshark_filter::CompiledFilter>,
    ) -> Result<Vec<PacketSummaryView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(search_packets(&capture, search, offset, limit, filter))
    }

    pub async fn list_streams(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StreamView>, ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        Ok(list_streams(&capture, offset, limit))
    }

    pub async fn get_stream(
        &self,
        session_id: &str,
        stream_id: u32,
    ) -> Result<(StreamView, Vec<PacketSummaryView>), ToolError> {
        let capture = self.acquire_capture(session_id).await?;

        get_stream(&capture, stream_id).ok_or_else(|| ToolError::StreamNotFound {
            session_id: session_id.to_string(),
            stream_id,
        })
    }

    // ── findings tools (keep lock — mutate cached findings) ──────────

    pub async fn audit_capture(
        &self,
        session_id: &str,
        profile: Option<&str>,
    ) -> Result<Vec<FindingView>, ToolError> {
        if let Some(p) = profile
            && !VALID_PROFILES.contains(&p)
        {
            return Err(ToolError::InvalidProfile {
                profile: p.to_string(),
                valid: VALID_PROFILES.join(", "),
            });
        }

        let capture = self.acquire_capture(session_id).await?;
        Ok(AuditEngine::audit_with_profile(&capture, profile))
    }

    pub async fn list_findings(
        &self,
        session_id: &str,
        severity: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<FindingView>, ToolError> {
        let mut sessions = self.sessions.lock().await;
        let session = require_session(&mut sessions, session_id)?;

        // Collect findings first (releases the mutable borrow from findings()).
        let mut results: Vec<FindingView> = session
            .findings()
            .iter()
            .filter(|finding| matches_filter(&finding.severity, severity))
            .filter(|finding| matches_filter(&finding.category, category))
            .cloned()
            .collect();

        // Merge escalation notes.
        for finding in &mut results {
            if let Some(esc) = session.get_escalation(&finding.id) {
                finding.escalated = true;
                finding.notes = Some(esc.notes.clone());
            }
        }

        Ok(results)
    }

    pub async fn explain_finding(
        &self,
        session_id: &str,
        finding_id: &str,
    ) -> Result<FindingView, ToolError> {
        let mut sessions = self.sessions.lock().await;
        let session = require_session(&mut sessions, session_id)?;

        session
            .findings()
            .iter()
            .find(|finding| finding.id == finding_id)
            .cloned()
            .ok_or_else(|| ToolError::FindingNotFound {
                session_id: session_id.to_string(),
                finding_id: finding_id.to_string(),
            })
    }

    pub async fn escalate_finding(
        &self,
        session_id: &str,
        finding_id: &str,
        notes: &str,
    ) -> Result<FindingView, ToolError> {
        let mut sessions = self.sessions.lock().await;
        let session = require_session(&mut sessions, session_id)?;

        // Verify the finding exists.
        let finding = session
            .findings()
            .iter()
            .find(|f| f.id == finding_id)
            .cloned()
            .ok_or_else(|| ToolError::FindingNotFound {
                session_id: session_id.to_string(),
                finding_id: finding_id.to_string(),
            })?;

        // Record escalation.
        session.escalate(finding_id.to_string(), notes.to_string());

        // Return the finding with escalation info.
        Ok(FindingView {
            escalated: true,
            notes: Some(notes.to_string()),
            ..finding
        })
    }

    // ── composite tools ──────────────────────────────────────────────

    pub async fn compare_captures(
        &self,
        session_id_a: &str,
        session_id_b: &str,
    ) -> Result<CaptureComparisonView, ToolError> {
        let cap_a = self.acquire_capture(session_id_a).await?;
        let cap_b = self.acquire_capture(session_id_b).await?;

        Ok(compare_analyzed_captures(&cap_a, &cap_b))
    }

    pub async fn summarize_capture(
        &self,
        session_id: &str,
    ) -> Result<CaptureSummaryView, ToolError> {
        // Clone the Arc for read-only work (lock released immediately).
        let capture = self.acquire_capture(session_id).await?;

        let protocols = summarize_protocols(&capture);
        let top_eps = top_endpoints(&capture, 10);

        let (first_timestamp, last_timestamp) = capture
            .packets()
            .iter()
            .filter_map(|p| p.frame().timestamp())
            .fold((None, None), |(first, _last), ts| {
                (first.or(Some(ts)), Some(ts))
            });

        let duration_ms = match (first_timestamp, last_timestamp) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first).as_millis() as u64),
            _ => None,
        };

        // Findings require mutable access (lazy cache), so re-acquire the lock.
        let finding_count = {
            let mut sessions = self.sessions.lock().await;
            let session = require_session(&mut sessions, session_id)?;
            session.findings().len()
        };

        Ok(CaptureSummaryView {
            packet_count: capture.packet_count(),
            stream_count: capture.tracker().stream_count(),
            first_timestamp: first_timestamp.map(format_timestamp),
            last_timestamp: last_timestamp.map(format_timestamp),
            duration_ms,
            protocols,
            top_endpoints: top_eps,
            finding_count,
        })
    }
}

fn require_session<'a>(
    sessions: &'a mut SessionManager,
    session_id: &str,
) -> Result<&'a mut crate::session::CaptureSession, ToolError> {
    sessions.expire_idle();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
    session.touch();
    Ok(session)
}

fn open_capture_response(capture: &AnalyzedCapture, session_id: &str) -> OpenCaptureResponse {
    OpenCaptureResponse {
        session_id: session_id.to_string(),
        backend: "native".to_string(),
        packet_count: capture.packet_count(),
        decode_issue_count: decode_issue_count(capture),
        protocol_counts: summarize_protocols(capture),
    }
}

fn decode_issue_count(capture: &AnalyzedCapture) -> usize {
    capture
        .packets()
        .iter()
        .map(|packet| packet.packet().issues().len())
        .sum()
}

/// Compare two `AnalyzedCapture` instances and produce a view.
///
/// This mirrors the logic in `fireshark_backend::compare` but operates
/// directly on `AnalyzedCapture` data so MCP sessions do not need to
/// re-open files through `BackendCapture`.
fn compare_analyzed_captures(a: &AnalyzedCapture, b: &AnalyzedCapture) -> CaptureComparisonView {
    use std::collections::BTreeSet;

    let a_hosts = extract_hosts_from_btree(a.endpoint_counts());
    let b_hosts = extract_hosts_from_btree(b.endpoint_counts());

    let a_host_set: BTreeSet<&str> = a_hosts.keys().map(|k| k.as_str()).collect();
    let b_host_set: BTreeSet<&str> = b_hosts.keys().map(|k| k.as_str()).collect();

    let mut new_hosts: Vec<HostDiffView> = b_host_set
        .difference(&a_host_set)
        .map(|host| HostDiffView {
            host: (*host).to_string(),
            count: b_hosts[*host],
        })
        .collect();
    new_hosts.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));

    let mut missing_hosts: Vec<HostDiffView> = a_host_set
        .difference(&b_host_set)
        .map(|host| HostDiffView {
            host: (*host).to_string(),
            count: a_hosts[*host],
        })
        .collect();
    missing_hosts.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));

    let a_proto_set: BTreeSet<&str> = a.protocol_counts().keys().map(|k| k.as_str()).collect();
    let b_proto_set: BTreeSet<&str> = b.protocol_counts().keys().map(|k| k.as_str()).collect();

    let mut new_protocols: Vec<ProtocolDiffView> = b_proto_set
        .difference(&a_proto_set)
        .map(|proto| ProtocolDiffView {
            name: (*proto).to_string(),
            count: b.protocol_counts()[*proto],
        })
        .collect();
    new_protocols.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

    let mut missing_protocols: Vec<ProtocolDiffView> = a_proto_set
        .difference(&b_proto_set)
        .map(|proto| ProtocolDiffView {
            name: (*proto).to_string(),
            count: a.protocol_counts()[*proto],
        })
        .collect();
    missing_protocols.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

    let a_ports = extract_ports_from_packets(a);
    let b_ports = extract_ports_from_packets(b);

    let a_port_set: BTreeSet<u16> = a_ports.keys().copied().collect();
    let b_port_set: BTreeSet<u16> = b_ports.keys().copied().collect();

    let mut new_ports: Vec<PortDiffView> = b_port_set
        .difference(&a_port_set)
        .map(|port| PortDiffView {
            port: *port,
            count: b_ports[port],
        })
        .collect();
    new_ports.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.port.cmp(&b.port)));

    let mut missing_ports: Vec<PortDiffView> = a_port_set
        .difference(&b_port_set)
        .map(|port| PortDiffView {
            port: *port,
            count: a_ports[port],
        })
        .collect();
    missing_ports.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.port.cmp(&b.port)));

    CaptureComparisonView {
        a_packet_count: a.packet_count(),
        b_packet_count: b.packet_count(),
        a_stream_count: a.tracker().stream_count(),
        b_stream_count: b.tracker().stream_count(),
        new_hosts,
        missing_hosts,
        new_protocols,
        missing_protocols,
        new_ports,
        missing_ports,
    }
}

fn extract_host_from_endpoint(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix('[')
        && let Some(bracket_pos) = rest.find(']')
    {
        return rest[..bracket_pos].to_string();
    }

    if let Some(colon_pos) = endpoint.rfind(':') {
        let maybe_port = &endpoint[colon_pos + 1..];
        if maybe_port.parse::<u16>().is_ok() {
            let before = &endpoint[..colon_pos];
            if !before.contains(':') {
                return before.to_string();
            }
        }
    }

    endpoint.to_string()
}

fn extract_hosts_from_btree(
    endpoint_counts: &std::collections::BTreeMap<String, usize>,
) -> std::collections::BTreeMap<String, usize> {
    let mut hosts = std::collections::BTreeMap::new();
    for (endpoint, count) in endpoint_counts {
        let host = extract_host_from_endpoint(endpoint);
        *hosts.entry(host).or_default() += count;
    }
    hosts
}

fn extract_port_from_addr(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(bracket_pos) = rest.find(']') {
            let after = &rest[bracket_pos + 1..];
            return after.strip_prefix(':').and_then(|s| s.parse().ok());
        }
        return None;
    }

    if let Some(colon_pos) = addr.rfind(':') {
        let before = &addr[..colon_pos];
        let port_str = &addr[colon_pos + 1..];
        if !before.contains(':') {
            return port_str.parse().ok();
        }
    }

    None
}

fn extract_ports_from_packets(capture: &AnalyzedCapture) -> std::collections::BTreeMap<u16, usize> {
    let mut ports = std::collections::BTreeMap::new();
    for packet in capture.packets() {
        let summary = packet.summary();
        for addr in [&summary.source, &summary.destination] {
            if let Some(port) = extract_port_from_addr(addr) {
                *ports.entry(port).or_default() += 1;
            }
        }
    }
    ports
}
