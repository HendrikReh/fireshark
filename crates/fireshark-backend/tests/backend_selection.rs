use fireshark_backend::BackendKind;

#[test]
fn backend_kind_parses_native_and_tshark() {
    assert_eq!(
        "native".parse::<BackendKind>().unwrap(),
        BackendKind::Native
    );
    assert_eq!(
        "tshark".parse::<BackendKind>().unwrap(),
        BackendKind::Tshark
    );
}

#[test]
fn backend_kind_rejects_unknown_values() {
    assert!("wireshark".parse::<BackendKind>().is_err());
}

#[test]
fn backend_kind_display_round_trips() {
    assert_eq!(BackendKind::Native.to_string(), "native");
    assert_eq!(BackendKind::Tshark.to_string(), "tshark");
}
