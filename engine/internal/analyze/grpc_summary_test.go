package analyze

import (
	"path/filepath"
	"testing"

	"github.com/vdparikh/ThreatLensAI/engine/internal/config"
)

func TestGRPCOnlyServiceLabelsMermaidGRPC(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := `package srv

import (
	"google.golang.org/grpc"
)

func New() *grpc.Server {
	return grpc.NewServer()
}
`
	if err := writeFile(filepath.Join(root, "server.go"), src); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Root:              root,
		ExcludePaths:      config.DefaultExcludePaths,
		IncludeExtensions: []string{".go"},
		MaxFiles:          10_000,
		MaxFileBytes:      512 * 1024,
	}
	m, err := BuildSystemModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.GoSummary == nil {
		t.Fatal("expected go_summary")
	}
	if !m.GoSummary.GRPCPresent {
		t.Fatal("expected grpc_present")
	}
	if m.GoSummary.HTTPHandlersDetected {
		t.Fatal("expected no http handlers")
	}
	if m.GoSummary.PrimaryAPIStyle != "grpc" {
		t.Fatalf("primary_api_style: got %q want grpc", m.GoSummary.PrimaryAPIStyle)
	}
	if m.MermaidFlow == "" {
		t.Fatal("expected mermaid")
	}
	if m.FlowGraph == nil {
		t.Fatal("expected flow_graph")
	}
	found := false
	for _, n := range m.FlowGraph.Nodes {
		if n.ID == "proc_http" && n.Label == "gRPC API surface" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected gRPC process node, got %+v", m.FlowGraph.Nodes)
	}
}

func TestGRPCCodegenFileWithoutImportStillDetected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Minimal stub: real codegen always imports grpc; test codegen path detection.
	codegen := `package kmsv1

import (
	"context"
	"google.golang.org/grpc"
)

type GreeterServer interface{}

func RegisterGreeterServer(s *grpc.Server, srv GreeterServer) {
}
`
	if err := writeFile(filepath.Join(root, "api_v1_grpc.pb.go"), codegen); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Root:              root,
		ExcludePaths:      config.DefaultExcludePaths,
		IncludeExtensions: []string{".go"},
		MaxFiles:          10_000,
		MaxFileBytes:      512 * 1024,
	}
	m, err := BuildSystemModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.GoSummary == nil || !m.GoSummary.GRPCPresent {
		t.Fatal("expected grpc from codegen path or imports")
	}
}
