mod support;

use std::time::Duration;

use fireshark_mcp::session::SessionManager;

#[test]
fn open_and_close_session_round_trip() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let mut sessions = SessionManager::new(8);

    let id = sessions.open_path(&fixture).unwrap();

    assert!(sessions.get(&id).is_some());

    sessions.close(&id).unwrap();

    assert!(sessions.get(&id).is_none());
}

#[test]
fn expired_sessions_are_rejected() {
    let fixture = support::repo_root().join("fixtures/smoke/minimal.pcap");
    let mut sessions = SessionManager::with_idle_timeout(8, Duration::ZERO);

    let id = sessions.open_path(&fixture).unwrap();

    sessions.expire_idle();

    assert!(sessions.get(&id).is_none());
}
