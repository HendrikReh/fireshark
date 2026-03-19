# Fireshark Crates

Fireshark is organized as a Cargo workspace with 8 crates. Each crate has its own README with usage details.

## Dependency Layers

```
                    fireshark-core          (zero external deps)
                   /    |    |    \
                  /     |    |     \
          -file   -dissectors  -filter   -tshark
                  \     |               /
                   \    |              /
                    fireshark-backend    (analysis, audit, compare)
                   /                \
                  /                  \
           fireshark-cli        fireshark-mcp
```

## Crate Index

| Crate | Purpose | Key Exports |
|-------|---------|-------------|
| [fireshark-core](fireshark-core/) | Domain types shared by all crates | `Frame`, `Packet`, `Layer`, `Pipeline`, `StreamTracker`, `PacketSummary` |
| [fireshark-file](fireshark-file/) | pcap/pcapng file reading | `CaptureReader`, `CaptureError` |
| [fireshark-dissectors](fireshark-dissectors/) | Protocol decoders (11 protocols) | `decode_packet`, `DecodeError` |
| [fireshark-filter](fireshark-filter/) | Display filter language | `compile`, `matches`, `unknown_field_names` |
| [fireshark-tshark](fireshark-tshark/) | tshark subprocess adapter | `discover`, `open`, `follow_stream`, `extract_certificates` |
| [fireshark-backend](fireshark-backend/) | Backend abstraction + domain logic | `BackendCapture`, `AnalyzedCapture`, `AuditEngine`, `compare` |
| [fireshark-cli](fireshark-cli/) | CLI binary (9 commands) | `fireshark` binary |
| [fireshark-mcp](fireshark-mcp/) | MCP server (21 tools) | `fireshark-mcp` binary |

## Key Rules

- **fireshark-core** has zero external dependencies — all types use `std` only
- **fireshark-cli** does not depend on **fireshark-mcp** — shared logic lives in **fireshark-backend**
- MCP view types (serde/schemars) stay in **fireshark-mcp** — no serialization leakage into core/backend
- Features are added as vertical slices touching the relevant crates, not as speculative frameworks

---

**Version:** 0.10.0 | **Last updated:** 2026-03-19
