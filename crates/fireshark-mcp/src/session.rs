use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::analysis::{AnalysisError, AnalyzedCapture};
use crate::audit::AuditEngine;
use crate::model::FindingView;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub struct EscalationNote {
    pub finding_id: String,
    pub notes: String,
    pub escalated_at: String,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),

    #[error("session not found: {0}")]
    NotFound(String),

    #[error("session limit reached: {max_sessions}")]
    LimitReached { max_sessions: usize },
}

#[derive(Debug, Clone)]
pub struct CaptureSession {
    pub id: String,
    capture: Arc<AnalyzedCapture>,
    pub last_accessed: Instant,
    findings: Option<Vec<FindingView>>,
    path: Option<PathBuf>,
    escalations: Vec<EscalationNote>,
}

impl CaptureSession {
    fn new(id: String, capture: AnalyzedCapture) -> Self {
        Self {
            id,
            capture: Arc::new(capture),
            last_accessed: Instant::now(),
            findings: None,
            path: None,
            escalations: Vec::new(),
        }
    }

    fn with_path(id: String, capture: AnalyzedCapture, path: PathBuf) -> Self {
        Self {
            id,
            capture: Arc::new(capture),
            last_accessed: Instant::now(),
            findings: None,
            path: Some(path),
            escalations: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    /// Borrow the capture through the `Arc`.
    pub fn capture(&self) -> &AnalyzedCapture {
        &self.capture
    }

    /// Clone the `Arc` so the caller can work with the capture after releasing
    /// any lock that guards this session.
    pub fn capture_arc(&self) -> Arc<AnalyzedCapture> {
        Arc::clone(&self.capture)
    }

    pub fn findings(&mut self) -> &[FindingView] {
        self.findings
            .get_or_insert_with(|| AuditEngine::audit(&self.capture))
            .as_slice()
    }

    /// The capture file path, if stored at session creation time.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Record an escalation note for a finding.
    pub fn escalate(&mut self, finding_id: String, notes: String) {
        let escalated_at = format_epoch_now();
        // Replace existing escalation for the same finding, if any.
        self.escalations.retain(|e| e.finding_id != finding_id);
        self.escalations.push(EscalationNote {
            finding_id,
            notes,
            escalated_at,
        });
    }

    /// Look up the escalation note for a given finding id.
    pub fn get_escalation(&self, finding_id: &str) -> Option<&EscalationNote> {
        self.escalations.iter().find(|e| e.finding_id == finding_id)
    }
}

#[derive(Debug)]
pub struct SessionManager {
    next_id: u64,
    max_sessions: usize,
    idle_timeout: Duration,
    sessions: BTreeMap<String, CaptureSession>,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self::with_idle_timeout(max_sessions, DEFAULT_IDLE_TIMEOUT)
    }

    pub fn with_idle_timeout(max_sessions: usize, idle_timeout: Duration) -> Self {
        Self {
            next_id: 1,
            max_sessions,
            idle_timeout,
            sessions: BTreeMap::new(),
        }
    }

    /// Open a capture file, parse it, and insert the session in one step.
    ///
    /// This is the original all-in-one helper kept for convenience in tests and
    /// simple call-sites that do not need to release the lock during I/O.
    pub fn open_path(&mut self, path: impl AsRef<Path>) -> Result<String, SessionError> {
        self.expire_idle();

        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::LimitReached {
                max_sessions: self.max_sessions,
            });
        }

        let id = generate_session_id(self.next_id);
        self.next_id += 1;

        let capture_path = path.as_ref().to_path_buf();
        let capture = AnalyzedCapture::open(path)?;
        let session = CaptureSession::with_path(id.clone(), capture, capture_path);
        self.sessions.insert(id.clone(), session);

        Ok(id)
    }

    /// Check whether there is room for another session without performing any
    /// I/O. Returns `Ok(())` when the limit has not been reached.
    pub fn check_limit(&self) -> Result<(), SessionError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::LimitReached {
                max_sessions: self.max_sessions,
            });
        }
        Ok(())
    }

    /// Insert a pre-built `AnalyzedCapture` into the manager and return the
    /// new session id. The caller is responsible for having called
    /// [`check_limit`] before performing the expensive I/O that produced
    /// `capture`.
    pub fn insert(&mut self, capture: AnalyzedCapture) -> String {
        self.expire_idle();

        let id = generate_session_id(self.next_id);
        self.next_id += 1;

        let session = CaptureSession::new(id.clone(), capture);
        self.sessions.insert(id.clone(), session);

        id
    }

    /// Insert a pre-built `AnalyzedCapture` with a known file path.
    pub fn insert_with_path(&mut self, capture: AnalyzedCapture, path: PathBuf) -> String {
        self.expire_idle();

        let id = generate_session_id(self.next_id);
        self.next_id += 1;

        let session = CaptureSession::with_path(id.clone(), capture, path);
        self.sessions.insert(id.clone(), session);

        id
    }

    pub fn get(&self, id: &str) -> Option<&CaptureSession> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut CaptureSession> {
        self.sessions.get_mut(id)
    }

    pub fn close(&mut self, id: &str) -> Result<(), SessionError> {
        self.sessions
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| SessionError::NotFound(id.to_string()))
    }

    pub fn expire_idle(&mut self) {
        let idle_timeout = self.idle_timeout;
        self.sessions
            .retain(|_, session| session.last_accessed.elapsed() < idle_timeout);
    }
}

/// Generate a session ID that is hard to guess.
///
/// Combines a monotonic counter with the current timestamp to produce a
/// hex string like `s-1-660abc12`. Not cryptographically random, but
/// unpredictable enough to prevent casual session-ID guessing over stdio.
fn generate_session_id(counter: u64) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix counter and timestamp into a single value
    let mixed = counter.wrapping_mul(6364136223846793005).wrapping_add(ts);
    format!("s-{counter}-{mixed:08x}")
}

/// Format the current wall-clock time as a simple epoch-seconds string.
/// Avoids pulling in `chrono` for a single formatting operation.
fn format_epoch_now() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs().to_string(),
        Err(_) => String::from("0"),
    }
}
