use rmcp::{
    ErrorData, Json, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::{
    CaptureComparisonView, CaptureDescriptionView, CaptureSummaryView, CertificateListView,
    CertificateView, CloseCaptureResponse, DecodeIssueListResponse, EndpointListResponse,
    FindingListResponse, OpenCaptureResponse, PacketDetailView, PacketListResponse,
    ProtocolSummaryResponse, StreamListResponse, StreamPacketsResponse, StreamPayloadView,
    StreamSegmentView,
};
use crate::query::PacketSearch;
use crate::tools::{ToolError, ToolService};

fn parse_filter_opt(
    filter: &Option<String>,
) -> Result<Option<fireshark_filter::CompiledFilter>, ErrorData> {
    match filter {
        Some(f) => fireshark_filter::compile(f)
            .map(Some)
            .map_err(|e| ErrorData::invalid_params(format!("invalid filter: {e}"), None)),
        None => Ok(None),
    }
}

type McpResult<T> = Result<Json<T>, ErrorData>;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FiresharkMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Offline packet-capture analysis and security-audit tools for .pcap and .pcapng files."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[derive(Clone)]
pub struct FiresharkMcpServer {
    tools: ToolService,
    tool_router: ToolRouter<Self>,
}

impl FiresharkMcpServer {
    pub fn new() -> Self {
        Self {
            tools: ToolService::new_default(),
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for FiresharkMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router(router = tool_router)]
impl FiresharkMcpServer {
    #[tool(description = "Open a packet capture file and create an analysis session")]
    async fn open_capture(
        &self,
        Parameters(request): Parameters<OpenCaptureRequest>,
    ) -> McpResult<OpenCaptureResponse> {
        let backend = request.backend.as_deref().unwrap_or("native");
        if backend != "native" {
            return Err(ErrorData::invalid_params(
                format!("backend '{backend}' is not yet supported for MCP sessions; use 'native'"),
                None,
            ));
        }
        self.tools
            .open_capture(request.path.as_str(), request.max_packets)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "Describe an existing analysis session")]
    async fn describe_capture(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<CaptureDescriptionView> {
        self.tools
            .describe_capture(&request.session_id)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "Close an analysis session")]
    async fn close_capture(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<CloseCaptureResponse> {
        self.tools
            .close_capture(&request.session_id)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "List packet summaries from a session")]
    async fn list_packets(
        &self,
        Parameters(request): Parameters<ListPacketsRequest>,
    ) -> McpResult<PacketListResponse> {
        let filter_expr = parse_filter_opt(&request.filter)?;
        self.tools
            .list_packets(
                &request.session_id,
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(100),
                request.protocol.as_deref(),
                request.has_issues,
                filter_expr.as_ref(),
            )
            .await
            .map(|packets| Json(PacketListResponse { packets }))
            .map_err(tool_error)
    }

    #[tool(description = "Get detailed layer and issue information for one packet")]
    async fn get_packet(
        &self,
        Parameters(request): Parameters<GetPacketRequest>,
    ) -> McpResult<PacketDetailView> {
        self.tools
            .get_packet(&request.session_id, request.packet_index)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "List decode issues found in a capture session")]
    async fn list_decode_issues(
        &self,
        Parameters(request): Parameters<ListDecodeIssuesRequest>,
    ) -> McpResult<DecodeIssueListResponse> {
        self.tools
            .list_decode_issues(
                &request.session_id,
                request.kind.as_deref(),
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(100),
            )
            .await
            .map(|issues| Json(DecodeIssueListResponse { issues }))
            .map_err(tool_error)
    }

    #[tool(description = "Summarize packet counts by protocol")]
    async fn summarize_protocols(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<ProtocolSummaryResponse> {
        self.tools
            .summarize_protocols(&request.session_id)
            .await
            .map(|protocols| Json(ProtocolSummaryResponse { protocols }))
            .map_err(tool_error)
    }

    #[tool(description = "Show the busiest endpoints in a capture session")]
    async fn top_endpoints(
        &self,
        Parameters(request): Parameters<TopEndpointsRequest>,
    ) -> McpResult<EndpointListResponse> {
        self.tools
            .top_endpoints(&request.session_id, request.limit.unwrap_or(10))
            .await
            .map(|endpoints| Json(EndpointListResponse { endpoints }))
            .map_err(tool_error)
    }

    #[tool(description = "Search packets by protocol, endpoint, port, free text, or issue state")]
    async fn search_packets(
        &self,
        Parameters(request): Parameters<SearchPacketsRequest>,
    ) -> McpResult<PacketListResponse> {
        let filter_expr = parse_filter_opt(&request.filter)?;
        let search = PacketSearch {
            protocol: request.protocol.as_deref(),
            source: request.source.as_deref(),
            destination: request.destination.as_deref(),
            port: request.port,
            text: request.text.as_deref(),
            has_issues: request.has_issues,
        };

        self.tools
            .search_packets(
                &request.session_id,
                &search,
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(100),
                filter_expr.as_ref(),
            )
            .await
            .map(|packets| Json(PacketListResponse { packets }))
            .map_err(tool_error)
    }

    #[tool(description = "Run the heuristic audit engine for a capture session")]
    async fn audit_capture(
        &self,
        Parameters(request): Parameters<AuditCaptureRequest>,
    ) -> McpResult<FindingListResponse> {
        self.tools
            .audit_capture(&request.session_id, request.profile.as_deref())
            .await
            .map(|findings| Json(FindingListResponse { findings }))
            .map_err(tool_error)
    }

    #[tool(description = "List audit findings, optionally filtered by severity or category")]
    async fn list_findings(
        &self,
        Parameters(request): Parameters<ListFindingsRequest>,
    ) -> McpResult<FindingListResponse> {
        self.tools
            .list_findings(
                &request.session_id,
                request.severity.as_deref(),
                request.category.as_deref(),
            )
            .await
            .map(|findings| Json(FindingListResponse { findings }))
            .map_err(tool_error)
    }

    #[tool(description = "Return full details for a single audit finding")]
    async fn explain_finding(
        &self,
        Parameters(request): Parameters<ExplainFindingRequest>,
    ) -> McpResult<crate::model::FindingView> {
        self.tools
            .explain_finding(&request.session_id, &request.finding_id)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "Escalate an audit finding with analyst notes")]
    async fn escalate_finding(
        &self,
        Parameters(request): Parameters<EscalateFindingRequest>,
    ) -> McpResult<crate::model::FindingView> {
        self.tools
            .escalate_finding(&request.session_id, &request.finding_id, &request.notes)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "List TCP/UDP conversation streams in a capture session")]
    async fn list_streams(
        &self,
        Parameters(request): Parameters<ListStreamsRequest>,
    ) -> McpResult<StreamListResponse> {
        self.tools
            .list_streams(
                &request.session_id,
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(100),
            )
            .await
            .map(|streams| Json(StreamListResponse { streams }))
            .map_err(tool_error)
    }

    #[tool(description = "Get a single stream with its packet summaries")]
    async fn get_stream(
        &self,
        Parameters(request): Parameters<GetStreamRequest>,
    ) -> McpResult<StreamPacketsResponse> {
        self.tools
            .get_stream(&request.session_id, request.stream_id)
            .await
            .map(|(stream, packets)| Json(StreamPacketsResponse { stream, packets }))
            .map_err(tool_error)
    }

    #[tool(
        description = "Get a one-shot summary of a capture: packets, streams, protocols, endpoints, findings"
    )]
    async fn summarize_capture(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<CaptureSummaryView> {
        self.tools
            .summarize_capture(&request.session_id)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "Compare two capture sessions and identify differences")]
    async fn compare_captures(
        &self,
        Parameters(request): Parameters<CompareCapturesRequest>,
    ) -> McpResult<CaptureComparisonView> {
        self.tools
            .compare_captures(&request.session_id_a, &request.session_id_b)
            .await
            .map(Json)
            .map_err(tool_error)
    }

    #[tool(description = "Get reassembled stream payload via tshark")]
    async fn get_stream_payload(
        &self,
        Parameters(request): Parameters<GetStreamPayloadRequest>,
    ) -> McpResult<StreamPayloadView> {
        let mode = match request.mode.as_deref().unwrap_or("tcp") {
            "tcp" => fireshark_backend::FollowMode::Tcp,
            "http" => fireshark_backend::FollowMode::Http,
            other => {
                return Err(ErrorData::invalid_params(
                    format!("unsupported follow mode: {other}; use 'tcp' or 'http'"),
                    None,
                ));
            }
        };

        let (tshark_path, _version) = fireshark_tshark::discover().map_err(|e| {
            ErrorData::internal_error(format!("tshark required for reassembly: {e}"), None)
        })?;

        let capture = self
            .tools
            .acquire_capture_for_reassembly(&request.session_id)
            .await
            .map_err(tool_error)?;

        let capture_path = capture
            .path()
            .ok_or_else(|| {
                ErrorData::internal_error("session has no capture path for reassembly", None)
            })?
            .to_path_buf();

        let payload = fireshark_tshark::follow::follow_stream(
            &tshark_path,
            &capture_path,
            request.stream_id,
            mode,
        )
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let segments = payload
            .segments
            .iter()
            .map(|seg| {
                let direction = match seg.direction {
                    fireshark_backend::Direction::ClientToServer => "client_to_server",
                    fireshark_backend::Direction::ServerToClient => "server_to_client",
                };
                StreamSegmentView {
                    direction: direction.to_string(),
                    data_hex: seg.data.iter().map(|b| format!("{b:02x}")).collect(),
                    data_len: seg.data.len(),
                }
            })
            .collect();

        Ok(Json(StreamPayloadView {
            stream_id: payload.stream_id,
            client: payload.client,
            server: payload.server,
            segments,
        }))
    }

    #[tool(description = "Extract TLS certificate information from a capture")]
    async fn get_certificates(
        &self,
        Parameters(request): Parameters<SessionRequest>,
    ) -> McpResult<CertificateListView> {
        let (tshark_path, _version) = fireshark_tshark::discover().map_err(|e| {
            ErrorData::internal_error(
                format!("tshark required for certificate extraction: {e}"),
                None,
            )
        })?;

        let capture = self
            .tools
            .acquire_capture_for_reassembly(&request.session_id)
            .await
            .map_err(tool_error)?;

        let capture_path = capture
            .path()
            .ok_or_else(|| {
                ErrorData::internal_error(
                    "session has no capture path for certificate extraction",
                    None,
                )
            })?
            .to_path_buf();

        let certs = fireshark_tshark::certs::extract_certificates(&tshark_path, &capture_path)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let certificates = certs
            .into_iter()
            .map(|c| CertificateView {
                packet_index: c.packet_index,
                common_name: c.common_name,
                san_dns_names: c.san_dns_names,
                organization: c.organization,
            })
            .collect();

        Ok(Json(CertificateListView { certificates }))
    }
}

pub async fn run_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let server = FiresharkMcpServer::new().serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}

fn tool_error(error: ToolError) -> ErrorData {
    match error {
        error @ ToolError::Session(crate::session::SessionError::NotFound(_))
        | error @ ToolError::PacketNotFound { .. }
        | error @ ToolError::FindingNotFound { .. }
        | error @ ToolError::StreamNotFound { .. } => {
            ErrorData::resource_not_found(error.to_string(), None)
        }
        error @ ToolError::Session(crate::session::SessionError::LimitReached { .. })
        | error @ ToolError::InvalidProfile { .. } => {
            ErrorData::invalid_params(error.to_string(), None)
        }
        error @ ToolError::Session(crate::session::SessionError::Analysis(_)) => {
            ErrorData::internal_error(error.to_string(), None)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct OpenCaptureRequest {
    path: String,
    /// Analysis backend: "native" (default) or "tshark".
    backend: Option<String>,
    /// Maximum number of packets to load (default 100,000, capped at 1,000,000).
    max_packets: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct SessionRequest {
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct AuditCaptureRequest {
    session_id: String,
    /// Audit profile: "security", "dns", or "quality". Omit to run all heuristics.
    profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListPacketsRequest {
    session_id: String,
    offset: Option<usize>,
    limit: Option<usize>,
    protocol: Option<String>,
    has_issues: Option<bool>,
    filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct GetPacketRequest {
    session_id: String,
    packet_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListDecodeIssuesRequest {
    session_id: String,
    kind: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct TopEndpointsRequest {
    session_id: String,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct SearchPacketsRequest {
    session_id: String,
    offset: Option<usize>,
    limit: Option<usize>,
    protocol: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    port: Option<u16>,
    text: Option<String>,
    has_issues: Option<bool>,
    filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListFindingsRequest {
    session_id: String,
    severity: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ExplainFindingRequest {
    session_id: String,
    finding_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EscalateFindingRequest {
    session_id: String,
    finding_id: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListStreamsRequest {
    session_id: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct GetStreamRequest {
    session_id: String,
    stream_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct CompareCapturesRequest {
    session_id_a: String,
    session_id_b: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct GetStreamPayloadRequest {
    session_id: String,
    stream_id: u32,
    /// Follow mode: "tcp" (default) or "http"
    mode: Option<String>,
}
