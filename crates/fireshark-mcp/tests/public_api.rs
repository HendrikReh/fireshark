use fireshark_mcp::{AnalyzedCapture, AuditEngine, VALID_PROFILES};

#[test]
fn root_reexports_expose_audit_api() {
    let capture = AnalyzedCapture::from_packets(Vec::new());

    let findings = AuditEngine::audit_with_profile(&capture, Some("security"));

    assert!(findings.is_empty());
    assert!(VALID_PROFILES.contains(&"security"));
}
