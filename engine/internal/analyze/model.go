package analyze

// FileEntry is one indexed source file in the system model.
type FileEntry struct {
	Path     string    `json:"path"`
	Language string    `json:"language"`
	Bytes    int64     `json:"bytes"`
	Go       *GoDetail `json:"go,omitempty"`
}

// SystemModel is JSON output for STRIDE / threat generation and diagrams.
type SystemModel struct {
	Version int `json:"version"`

	Root       string         `json:"root"`
	FileCount  int            `json:"file_count"`
	TotalBytes int64          `json:"total_bytes"`
	Languages  map[string]int `json:"languages"`
	Files      []FileEntry    `json:"files"`
	Truncated  bool           `json:"truncated"`

	// Heuristic high-signal findings from source scanning (for LLM grounding).
	SecuritySignals []SecuritySignal `json:"security_signals,omitempty"`

	// Go / HTTP (populated when Go sources are present)
	GoSummary       *GoSummary   `json:"go_summary,omitempty"`
	HTTPRoutes      []RouteEntry `json:"http_routes,omitempty"`
	RoutesTruncated bool         `json:"routes_truncated,omitempty"`
	FlowGraph       *FlowGraph   `json:"flow_graph,omitempty"`
	MermaidFlow     string       `json:"mermaid_flow,omitempty"`
	GRPCEndpoints   []GRPCEndpoint `json:"grpc_endpoints,omitempty"`
}
