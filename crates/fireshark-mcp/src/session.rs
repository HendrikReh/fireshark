use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::analysis::{AnalysisError, AnalyzedCapture};
use crate::audit::AuditEngine;
use crate::model::FindingView;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

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
    pub capture: AnalyzedCapture,
    pub last_accessed: Instant,
    findings: Option<Vec<FindingView>>,
}

impl CaptureSession {
    fn new(id: String, capture: AnalyzedCapture) -> Self {
        Self {
            id,
            capture,
            last_accessed: Instant::now(),
            findings: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    pub fn findings(&mut self) -> &[FindingView] {
        self.findings
            .get_or_insert_with(|| AuditEngine::audit(&self.capture))
            .as_slice()
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

    pub fn open_path(&mut self, path: impl AsRef<Path>) -> Result<String, SessionError> {
        self.expire_idle();

        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::LimitReached {
                max_sessions: self.max_sessions,
            });
        }

        let id = format!("session-{}", self.next_id);
        self.next_id += 1;

        let capture = AnalyzedCapture::open(path)?;
        let session = CaptureSession::new(id.clone(), capture);
        self.sessions.insert(id.clone(), session);

        Ok(id)
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
