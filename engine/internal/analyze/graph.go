package analyze

import (
	"sort"
	"strings"
)

// FlowNodeKind categorizes diagram nodes for trust-boundary style flows.
type FlowNodeKind string

const (
	KindActor    FlowNodeKind = "actor"
	KindProcess  FlowNodeKind = "process"
	KindData     FlowNodeKind = "datastore"
	KindExternal FlowNodeKind = "external"
)

// FlowNode is a node in the architecture / data-flow graph.
type FlowNode struct {
	ID    string       `json:"id"`
	Label string       `json:"label"`
	Kind  FlowNodeKind `json:"kind"`
}

// FlowEdge connects two nodes (directed).
type FlowEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label,omitempty"`
}

// FlowGraph is a simplified DFD-style graph for visualization and STRIDE context.
type FlowGraph struct {
	Nodes []FlowNode `json:"nodes"`
	Edges []FlowEdge `json:"edges"`
}

// GoSummary aggregates signals useful for threat modeling.
type GoSummary struct {
	RouteCount         int      `json:"route_count"`
	HTTPRouteCount     int      `json:"http_route_count"`
	GRPCRouteCount     int      `json:"grpc_route_count"`
	FrameworksDetected []string `json:"frameworks_detected"`
	DatabaseHints      []string `json:"database_hints"`
	ExternalHTTP       bool     `json:"external_http_clients"`
	// GRPCPresent is true when code imports google.golang.org/grpc or contains typical gRPC codegen (*_grpc.pb.go).
	GRPCPresent bool `json:"grpc_present"`
	// HTTPHandlersDetected is true when best-effort HTTP route extraction found at least one route.
	HTTPHandlersDetected bool `json:"http_handlers_detected"`
	// PrimaryAPIStyle is a heuristic: grpc, http, mixed, or minimal (for LLM / diagram labels).
	PrimaryAPIStyle string `json:"primary_api_style,omitempty"`
}

const maxRoutesForSummary = 2000

// buildGoSummaryAndGraph derives summary + flow graph from collected routes and import sets.
// grpcCodegenFile is true when at least one *_grpc.pb.go (or path suggests buf/grpc codegen) was indexed.
func buildGoSummaryAndGraph(routes []RouteEntry, allImports map[string]struct{}, grpcCodegenFile bool, grpcEndpoints []GRPCEndpoint) (*GoSummary, *FlowGraph) {
	totalSeen := len(routes)
	if len(routes) > maxRoutesForSummary {
		routes = routes[:maxRoutesForSummary]
	}

	fwSet := make(map[string]struct{})
	for _, r := range routes {
		if r.Framework != "" && r.Framework != "unknown" {
			fwSet[r.Framework] = struct{}{}
		}
	}
	var frameworks []string
	for f := range fwSet {
		frameworks = append(frameworks, f)
	}
	sort.Strings(frameworks)

	dbHints := databaseHintsFromImports(allImports)
	extHTTP := hasHTTPClientImports(allImports)

	httpHandlers := totalSeen > 0
	grpcRouteCount := len(grpcEndpoints)
	grpcImp := grpcImportPresent(allImports)
	grpcPresent := grpcImp || grpcCodegenFile || grpcRouteCount > 0
	var primary string
	switch {
	case httpHandlers && grpcPresent:
		primary = "mixed"
	case httpHandlers:
		primary = "http"
	case grpcPresent:
		primary = "grpc"
	default:
		primary = "minimal"
	}

	summary := &GoSummary{
		RouteCount:           totalSeen + grpcRouteCount,
		HTTPRouteCount:       totalSeen,
		GRPCRouteCount:       grpcRouteCount,
		FrameworksDetected: frameworks,
		DatabaseHints:        dbHints,
		ExternalHTTP:         extHTTP,
		GRPCPresent:          grpcPresent,
		HTTPHandlersDetected: httpHandlers,
		PrimaryAPIStyle:      primary,
	}

	g := buildFlowGraph(routes, summary)
	return summary, g
}

func grpcImportPresent(imports map[string]struct{}) bool {
	for p := range imports {
		if p == "google.golang.org/grpc" || strings.HasPrefix(p, "google.golang.org/grpc/") {
			return true
		}
	}
	return false
}

func databaseHintsFromImports(imports map[string]struct{}) []string {
	var hints []string
	add := func(s string) {
		for _, x := range hints {
			if x == s {
				return
			}
		}
		hints = append(hints, s)
	}
	for p := range imports {
		switch {
		case strings.Contains(p, "database/sql"):
			add("sql")
		case strings.Contains(p, "gorm.io"):
			add("gorm")
		case strings.Contains(p, "go.mongodb.org/mongo-driver"):
			add("mongodb")
		case strings.Contains(p, "github.com/redis/go-redis"), strings.Contains(p, "github.com/go-redis/redis"):
			add("redis")
		case strings.Contains(p, "github.com/lib/pq"), strings.Contains(p, "github.com/jackc/pgx"):
			add("postgres")
		case strings.Contains(p, "github.com/go-sql-driver/mysql"):
			add("mysql")
		case strings.Contains(p, "github.com/elastic/go-elasticsearch"):
			add("elasticsearch")
		}
	}
	sort.Strings(hints)
	return hints
}

func hasHTTPClientImports(imports map[string]struct{}) bool {
	for p := range imports {
		if p == "net/http" || strings.Contains(p, "google.golang.org/api") {
			return true
		}
	}
	return false
}

func buildFlowGraph(routes []RouteEntry, summary *GoSummary) *FlowGraph {
	procID := "proc_http"
	procLabel := "Application entry (no HTTP routes indexed)"
	edgeInLabel := "requests"
	switch summary.PrimaryAPIStyle {
	case "grpc":
		procLabel = "gRPC API surface"
		edgeInLabel = "gRPC"
	case "http":
		procLabel = "HTTP surface (handlers)"
	case "mixed":
		procLabel = "HTTP and gRPC API surface"
		edgeInLabel = "HTTP / gRPC"
	case "minimal":
		if summary.GRPCPresent {
			procLabel = "gRPC API surface"
			edgeInLabel = "gRPC"
		}
	}

	nodes := []FlowNode{
		{ID: "actor_user", Label: "User / Client", Kind: KindActor},
		{ID: procID, Label: procLabel, Kind: KindProcess},
	}
	edges := []FlowEdge{
		{From: "actor_user", To: procID, Label: edgeInLabel},
	}

	if len(summary.DatabaseHints) > 0 {
		nodes = append(nodes, FlowNode{
			ID:    "data_store",
			Label: "Data stores (" + strings.Join(summary.DatabaseHints, ", ") + ")",
			Kind:  KindData,
		})
		dbEdge := "queries"
		if summary.PrimaryAPIStyle == "grpc" || (summary.PrimaryAPIStyle == "minimal" && summary.GRPCPresent && !summary.HTTPHandlersDetected) {
			dbEdge = "data access"
		}
		edges = append(edges, FlowEdge{From: procID, To: "data_store", Label: dbEdge})
	}

	if summary.ExternalHTTP {
		nodes = append(nodes, FlowNode{
			ID:    "ext_services",
			Label: "External HTTP APIs",
			Kind:  KindExternal,
		})
		edges = append(edges, FlowEdge{From: procID, To: "ext_services", Label: "outbound"})
	}

	return &FlowGraph{Nodes: nodes, Edges: edges}
}
