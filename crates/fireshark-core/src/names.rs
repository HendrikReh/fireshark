//! Human-readable name lookups for protocol constants.
//!
//! These are presentation/formatting helpers used by the CLI and MCP crates.
//! They live in core so that every downstream consumer can share the same
//! mapping tables without depending on the dissectors crate.

/// Lookup a TLS cipher suite ID to a human-readable name.
pub fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        // ECDHE+RSA
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        // ECDHE+ECDSA
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        // DHE+RSA
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        // RSA
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        _ => "Unknown",
    }
}

/// Lookup a TLS signature algorithm ID to a human-readable name.
pub fn sig_alg_name(id: u16) -> &'static str {
    match id {
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        _ => "Unknown",
    }
}

/// Lookup a TLS named group ID to a human-readable name.
pub fn named_group_name(id: u16) -> &'static str {
    match id {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001D => "x25519",
        0x001E => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        _ => "Unknown",
    }
}

/// Lookup a TLS version number to a human-readable name.
pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Lookup a DNS query type to a human-readable name.
pub fn dns_qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "Unknown",
    }
}

/// Lookup a DNS response code to a human-readable name.
pub fn dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "No Error",
        1 => "Format Error",
        2 => "Server Failure",
        3 => "NXDOMAIN",
        4 => "Not Implemented",
        5 => "Refused",
        _ => "Unknown",
    }
}
