use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;

use thiserror::Error;

use crate::analysis::{AnalyzedCapture, DEFAULT_MAX_PACKETS};
use crate::filter::matches_filter;
use crate::model::{
    CaptureDescriptionView, CaptureSummaryView, CloseCaptureResponse, DecodeIssueEntryView,
    EndpointCountView, FindingView, OpenCaptureResponse, PacketDetailView, PacketSummaryView,
    ProtocolCountView, StreamView,
};
use crate::query::{
    PacketSearch, format_timestamp, get_packet, get_stream, list_decode_issues, list_packets,
    list_streams, search_packets, summarize_protocols, top_endpoints,
};
use crate::session::{SessionError, SessionManager};

const DEFAULT_MAX_SESSIONS: usize = 8;

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
        let session_id = sessions.insert(capture);

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
        filter: Option<&fireshark_filter::ast::Expr>,
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
        filter: Option<&fireshark_filter::ast::Expr>,
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

    pub async fn audit_capture(&self, session_id: &str) -> Result<Vec<FindingView>, ToolError> {
        let mut sessions = self.sessions.lock().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(session.findings().to_vec())
    }

    pub async fn list_findings(
        &self,
        session_id: &str,
        severity: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<FindingView>, ToolError> {
        let mut sessions = self.sessions.lock().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(session
            .findings()
            .iter()
            .filter(|finding| matches_filter(&finding.severity, severity))
            .filter(|finding| matches_filter(&finding.category, category))
            .cloned()
            .collect())
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

    // ── composite tools ──────────────────────────────────────────────

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
