use std::path::Path;
use std::sync::Arc;

use tokio::sync::{Mutex, MutexGuard};

use thiserror::Error;

use crate::filter::matches_filter;
use crate::model::{
    CaptureDescriptionView, CloseCaptureResponse, DecodeIssueEntryView, EndpointCountView,
    FindingView, OpenCaptureResponse, PacketDetailView, PacketSummaryView, ProtocolCountView,
};
use crate::query::{
    PacketSearch, get_packet, list_decode_issues, list_packets, search_packets,
    summarize_protocols, top_endpoints,
};
use crate::session::{CaptureSession, SessionError, SessionManager};

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

    pub async fn open_capture(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<OpenCaptureResponse, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session_id = sessions.open_path(path)?;
        // open_path already called expire_idle and inserted the session, so
        // fetch it directly without re-expiring (which could drop it under
        // very short idle timeouts).
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.touch();
        Ok(open_capture_response(session))
    }

    pub async fn describe_capture(
        &self,
        session_id: &str,
    ) -> Result<CaptureDescriptionView, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(CaptureDescriptionView {
            session_id: session.id.clone(),
            packet_count: session.capture.packet_count(),
            decode_issue_count: decode_issue_count(&session.capture),
            protocol_counts: summarize_protocols(&session.capture),
            top_endpoints: top_endpoints(&session.capture, 10),
        })
    }

    pub async fn close_capture(&self, session_id: &str) -> Result<CloseCaptureResponse, ToolError> {
        let mut sessions = self.lock_sessions().await;
        sessions.close(session_id)?;

        Ok(CloseCaptureResponse {
            session_id: session_id.to_string(),
            closed: true,
        })
    }

    pub async fn list_packets(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
        protocol: Option<&str>,
        has_issues: Option<bool>,
    ) -> Result<Vec<PacketSummaryView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(list_packets(
            &session.capture,
            offset,
            limit,
            protocol,
            has_issues,
        ))
    }

    pub async fn get_packet(
        &self,
        session_id: &str,
        index: usize,
    ) -> Result<PacketDetailView, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        get_packet(&session.capture, index).ok_or_else(|| ToolError::PacketNotFound {
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
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(list_decode_issues(&session.capture, kind, offset, limit))
    }

    pub async fn summarize_protocols(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtocolCountView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(summarize_protocols(&session.capture))
    }

    pub async fn top_endpoints(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<EndpointCountView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(top_endpoints(&session.capture, limit))
    }

    pub async fn search_packets(
        &self,
        session_id: &str,
        search: &PacketSearch<'_>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<PacketSummaryView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(search_packets(&session.capture, search, offset, limit))
    }

    pub async fn audit_capture(&self, session_id: &str) -> Result<Vec<FindingView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
        let session = require_session(&mut sessions, session_id)?;

        Ok(session.findings().to_vec())
    }

    pub async fn list_findings(
        &self,
        session_id: &str,
        severity: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<FindingView>, ToolError> {
        let mut sessions = self.lock_sessions().await;
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
        let mut sessions = self.lock_sessions().await;
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

    async fn lock_sessions(&self) -> MutexGuard<'_, SessionManager> {
        self.sessions.lock().await
    }
}

fn require_session<'a>(
    sessions: &'a mut SessionManager,
    session_id: &str,
) -> Result<&'a mut CaptureSession, ToolError> {
    sessions.expire_idle();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
    session.touch();
    Ok(session)
}

fn open_capture_response(session: &CaptureSession) -> OpenCaptureResponse {
    OpenCaptureResponse {
        session_id: session.id.clone(),
        packet_count: session.capture.packet_count(),
        decode_issue_count: decode_issue_count(&session.capture),
        protocol_counts: summarize_protocols(&session.capture),
    }
}

fn decode_issue_count(capture: &crate::analysis::AnalyzedCapture) -> usize {
    capture
        .packets()
        .iter()
        .map(|packet| packet.packet().issues().len())
        .sum()
}
