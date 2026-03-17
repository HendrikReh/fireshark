# TLS Dissector — Design Spec

## Purpose

Add TLS ClientHello and ServerHello dissectors to fireshark. TLS is dispatched by payload heuristic (`0x16 0x03`) on any TCP port, not just 443. The primary value is SNI extraction — identifying which domain is being accessed in encrypted traffic.

## TCP Application-Layer Dispatch

Currently `append_application_layer` only extracts payloads for `Layer::Udp`. This spec requires extending it to also extract TCP payloads.

For `Layer::Tcp`, the application payload starts after `data_offset * 4` bytes. The orchestrator computes:

```rust
Layer::Tcp(tcp) => {
    let hdr_len = usize::from(tcp.data_offset) * 4;
    (tcp.source_port, tcp.destination_port, hdr_len)
}
```

This is the same pattern already used for UDP (`hdr_len = 8`). The TCP branch is added alongside the existing UDP branch in `append_application_layer`.

## TLS Dispatch

After DNS port check (which only fires on UDP), add a TLS heuristic for TCP payloads:

```rust
if app_payload.len() >= 6
    && app_payload[0] == 0x16           // ContentType: Handshake
    && app_payload[1] == 0x03           // TLS major version
    && app_payload[2] <= 0x03           // TLS minor version (0x00-0x03)
    && (app_payload[5] == 0x01 || app_payload[5] == 0x02)  // ClientHello or ServerHello
{
    // dispatch to tls::parse
}
```

The heuristic checks 6 bytes: the TLS record header (3 bytes) + enough to see the handshake type at offset 5. This avoids false-positive `Malformed` issues on non-TLS TCP traffic that happens to start with `0x16 0x03` — if the handshake type is not 0x01 or 0x02, the heuristic simply doesn't fire and no TLS layer is added.

## Layer Types

Two separate `Layer` variants — they have different field sets.

### TlsClientHelloLayer

```rust
pub struct TlsClientHelloLayer {
    pub record_version: u16,
    pub client_version: u16,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
}
```

### TlsServerHelloLayer

```rust
pub struct TlsServerHelloLayer {
    pub record_version: u16,
    pub server_version: u16,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub selected_version: Option<u16>,
    pub alpn: Option<String>,
    pub key_share_group: Option<u16>,
}
```

Both variants report `"TLS"` from `Layer::name()`.

Export `TlsClientHelloLayer`, `TlsServerHelloLayer` from `fireshark-core::lib`.

## TLS Record and Handshake Format

### TLS record header (5 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 1 | content_type (0x16 = Handshake) |
| 1 | 2 | record_version (e.g., 0x0301) |
| 3 | 2 | record_length |

### Handshake header (4 bytes, at offset 5)

| Offset | Length | Field |
|--------|--------|-------|
| 5 | 1 | handshake_type (0x01 = ClientHello, 0x02 = ServerHello) |
| 6 | 3 | handshake_length (24-bit) |

### ClientHello body (starting at offset 9)

| Offset | Length | Field |
|--------|--------|-------|
| 9 | 2 | client_version |
| 11 | 32 | random |
| 43 | 1 | session_id_length |
| 44 | session_id_length | session_id (skip) |
| next | 2 | cipher_suites_length (in bytes) |
| next | cipher_suites_length | cipher_suites (2 bytes each) |
| next | 1 | compression_methods_length |
| next | compression_methods_length | compression_methods (1 byte each) |
| next | 2 | extensions_length |
| next | extensions_length | extensions |

### ServerHello body (starting at offset 9)

Same prefix as ClientHello (version, random, session_id) but then:
- 2 bytes: selected cipher_suite
- 1 byte: selected compression_method
- 2 bytes: extensions_length
- extensions

### Extension format

Each extension: type (2) + length (2) + data (length bytes).

Parsed extensions:

| Extension | Type ID | ClientHello parsing | ServerHello parsing |
|-----------|---------|--------------------|--------------------|
| SNI | 0x0000 | Extract first hostname from server name list | N/A |
| ALPN | 0x0010 | List of protocol names | Single selected protocol |
| Supported versions | 0x002B | List of version u16s | Single selected version u16 |
| Signature algorithms | 0x000D | List of algorithm u16 pairs | N/A |
| Key share | 0x0033 | List of named group u16 IDs (skip key data) | Single named group u16 |

Unknown extensions are skipped by advancing `length` bytes.

### Extension sub-format details

**SNI (0x0000)** — RFC 6066:
- 2 bytes: server_name_list_length
- For each entry: 1 byte name_type (0x00 = hostname), 2 bytes name_length, name_length bytes of hostname
- Extract the first entry with name_type 0x00

**ALPN (0x0010)** — RFC 7301:
- 2 bytes: protocol_name_list_length
- For each entry: 1 byte protocol_name_length, protocol_name_length bytes of name (e.g., "h2", "http/1.1")
- ClientHello: collect all entries into `Vec<String>`
- ServerHello: extract single selected protocol

**Supported Versions (0x002B)** — RFC 8446 section 4.2.1:
- ClientHello: 1 byte list_length, then list_length/2 entries of 2-byte version u16
- ServerHello: single 2-byte version u16 (no length prefix)

**Signature Algorithms (0x000D)** — RFC 8446 section 4.2.3:
- 2 bytes: algorithms_length
- algorithms_length/2 entries of 2-byte SignatureScheme u16

**Key Share (0x0033)** — RFC 8446 section 4.2.8:
- ClientHello: 2 bytes client_shares_length, then for each entry: 2 bytes named_group, 2 bytes key_exchange_length, key_exchange_length bytes (skip key data). Extract only the named_group IDs.
- ServerHello: single entry: 2 bytes named_group, 2 bytes key_exchange_length, key_exchange_length bytes. Extract the named_group ID.

### Safety limits

- Max cipher suites: 200 (prevent allocation from crafted cipher_suites_length)
- Max extensions parsed: 50
- Max extension data examined: bounded by record_length from the TLS record header
- All slice accesses bounds-checked against `bytes.len()`
- If any field is truncated, return what was parsed so far (partial layer is better than nothing)

## Dissector Module

New file: `crates/fireshark-dissectors/src/tls.rs`

```rust
pub fn parse(bytes: &[u8], offset: usize) -> Result<Layer, DecodeError>
```

Parses the TLS record header, then dispatches by handshake_type:
- 0x01 → `parse_client_hello` → `Layer::TlsClientHello(...)`
- 0x02 → `parse_server_hello` → `Layer::TlsServerHello(...)`
- other → `DecodeError::Malformed("unsupported TLS handshake type")`

Returns `DecodeError::Truncated` if the record header is incomplete (< 5 bytes) or the handshake header is incomplete (< 9 bytes).

### Cipher suite name lookup

Static function `cipher_suite_name(id: u16) -> &'static str` in `tls.rs`. Maps ~30 common suites:

- TLS 1.3: AES_128_GCM_SHA256 (0x1301), AES_256_GCM_SHA384 (0x1302), CHACHA20_POLY1305_SHA256 (0x1303)
- ECDHE+RSA: with AES_128_GCM (0xC02F), AES_256_GCM (0xC030), AES_128_CBC (0xC013), AES_256_CBC (0xC014)
- ECDHE+ECDSA: with AES_128_GCM (0xC02B), AES_256_GCM (0xC02C)
- DHE+RSA: with AES_128_GCM (0x009E), AES_256_GCM (0x009F)
- RSA: with AES_128_GCM (0x009C), AES_256_GCM (0x009D), AES_128_CBC (0x002F), AES_256_CBC (0x0035)

Unknown: `"Unknown"`.

### Signature algorithm name lookup

Static function `sig_alg_name(id: u16) -> &'static str`. Common algorithms:
- 0x0401 rsa_pkcs1_sha256, 0x0501 rsa_pkcs1_sha384, 0x0601 rsa_pkcs1_sha512
- 0x0403 ecdsa_secp256r1_sha256, 0x0503 ecdsa_secp384r1_sha384
- 0x0804 rsa_pss_rsae_sha256, 0x0805 rsa_pss_rsae_sha384, 0x0806 rsa_pss_rsae_sha512
- 0x0807 ed25519, 0x0808 ed448

### Named group lookup

Static function `named_group_name(id: u16) -> &'static str`:
- 0x0017 secp256r1, 0x0018 secp384r1, 0x0019 secp521r1
- 0x001D x25519, 0x001E x448
- 0x0100 ffdhe2048, 0x0101 ffdhe3072

## Filter Integration

Add `Tls` to the `Protocol` enum. `"tls"` keyword in lexer/parser. The `has_protocol` check matches both `Layer::TlsClientHello` and `Layer::TlsServerHello`.

Filter fields:

| Field | Source | Type | Notes |
|-------|--------|------|-------|
| `tls.handshake.type` | 1=ClientHello, 2=ServerHello | Integer | |
| `tls.record_version` | record_version from TLS record header | Integer | Usually 0x0301 |
| `tls.client_version` | ClientHello client_version field | Integer | Returns None for ServerHello |
| `tls.selected_version` | ServerHello supported_versions extension | Integer | Returns None for ClientHello |
| `tls.cipher_suite` | ServerHello selected suite | Integer | Returns None for ClientHello |

`tls.sni` is not filterable in v1 (needs string operators, issue #10).

## CLI Integration

**Color:** `"TLS"` → `Color::BrightGreen`

**Detail rendering:**

ClientHello:
```
▸ TLS ClientHello
    Record Version: TLS 1.0 (0x0301)
    Client Version: TLS 1.2 (0x0303)
    SNI: example.com
    Cipher Suites (16):
      TLS_AES_128_GCM_SHA256 (0x1301)
      TLS_AES_256_GCM_SHA384 (0x1302)
      ...
    Compression: null
    ALPN: h2, http/1.1
    Supported Versions: TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    Signature Algorithms: ecdsa_secp256r1_sha256 (0x0403), rsa_pss_rsae_sha256 (0x0804), ...
    Key Share Groups: x25519 (0x001D), secp256r1 (0x0017)
```

ServerHello:
```
▸ TLS ServerHello
    Record Version: TLS 1.2 (0x0303)
    Server Version: TLS 1.2 (0x0303)
    Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
    Compression: null
    Selected Version: TLS 1.3 (0x0304)
    ALPN: h2
    Key Share Group: x25519 (0x001D)
```

Version formatting: `tls_version_name(v: u16) -> &'static str` — 0x0300 "SSL 3.0", 0x0301 "TLS 1.0", 0x0302 "TLS 1.1", 0x0303 "TLS 1.2", 0x0304 "TLS 1.3".

## MCP LayerView

Two new variants in `LayerView`:

```rust
TlsClientHello {
    record_version: u16,
    client_version: u16,
    cipher_suites: Vec<CipherSuiteView>,
    compression_methods: Vec<u8>,
    sni: Option<String>,
    alpn: Vec<String>,
    supported_versions: Vec<u16>,
    signature_algorithms: Vec<SignatureAlgorithmView>,
    key_share_groups: Vec<NamedGroupView>,
}

TlsServerHello {
    record_version: u16,
    server_version: u16,
    cipher_suite: CipherSuiteView,
    compression_method: u8,
    selected_version: Option<u16>,
    alpn: Option<String>,
    key_share_group: Option<NamedGroupView>,
}
```

Where:
```rust
pub struct CipherSuiteView { pub id: u16, pub name: String }
pub struct SignatureAlgorithmView { pub id: u16, pub name: String }
pub struct NamedGroupView { pub id: u16, pub name: String }
```

## Fixtures

- `fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin` — realistic ClientHello with SNI "example.com", ALPN ["h2", "http/1.1"], supported_versions [TLS 1.3, 1.2], ~280 bytes
- `fixtures/bytes/ethernet_ipv4_tcp_tls_server_hello.bin` — ServerHello selecting TLS 1.3, AES_128_GCM, h2, ~120 bytes

## Testing

- `decodes_tls_client_hello` — fixture, assert SNI, cipher suite count, ALPN, supported_versions
- `decodes_tls_server_hello` — fixture, assert cipher_suite, selected_version, ALPN
- `tls_heuristic_dispatches_on_non_443` — TLS payload on port 8443, verify TLS layer present
- `non_tls_tcp_not_dispatched` — TCP payload starting with 0x47 (HTTP GET), no TLS layer
- `tls_truncated_record` — < 5 bytes TCP payload with 0x16 prefix, truncation issue
- `tls_layer_names` — verify ["Ethernet", "IPv4", "TCP", "TLS"]
- Filter: `"tls"` on ClientHello packet → true
- Filter: `"tls.handshake.type == 1"` on ClientHello → true

## New Files

- `crates/fireshark-dissectors/src/tls.rs`
- `crates/fireshark-dissectors/tests/tls.rs`
- `fixtures/bytes/ethernet_ipv4_tcp_tls_client_hello.bin`
- `fixtures/bytes/ethernet_ipv4_tcp_tls_server_hello.bin`

## Modified Files

- `crates/fireshark-core/src/layer.rs` — add TlsClientHelloLayer, TlsServerHelloLayer, Layer variants
- `crates/fireshark-core/src/lib.rs` — export new types
- `crates/fireshark-dissectors/src/lib.rs` — add mod tls, extend append_application_layer for TCP payloads + TLS heuristic dispatch
- `crates/fireshark-filter/src/ast.rs` — add Tls to Protocol enum
- `crates/fireshark-filter/src/lexer.rs` — add "tls" keyword
- `crates/fireshark-filter/src/parser.rs` — handle Tls token
- `crates/fireshark-filter/src/evaluate.rs` — tls.* fields, Protocol::Tls presence check (both variants)
- `crates/fireshark-cli/src/color.rs` — TLS → BrightGreen
- `crates/fireshark-cli/src/detail.rs` — render_tls_client_hello, render_tls_server_hello
- `crates/fireshark-mcp/src/model.rs` — TlsClientHello/TlsServerHello variants, view types, from_layer

Note: Adding two new `Layer` variants will break any exhaustive `match` on `Layer` across the codebase. Known sites: `render_layer` in `detail.rs` (listed above), `transport_ports` in `packet.rs` (wildcard, safe), `format_endpoints` in `summary.rs` (wildcard, safe), `from_layer` in `model.rs` (listed above). The implementer should run `cargo check --workspace` early to find all compile errors.

## Out of Scope

- Certificate parsing (requires TCP reassembly — deferred to v0.5)
- TLS session resumption (PSK, session tickets)
- Encrypted extensions (TLS 1.3 encrypted handshake messages after ServerHello)
- Alert and ChangeCipherSpec record types
- `tls.sni` string filtering (needs string operators, issue #10)
- TLS over UDP (DTLS)
