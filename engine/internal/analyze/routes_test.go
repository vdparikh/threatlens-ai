package analyze

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestExtractRoutesGin(t *testing.T) {
	t.Parallel()
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {})
	r.POST("/api/v1/items", func(c *gin.Context) {})
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	imports := collectImports(f)
	routes := extractRoutes(f, fset, "cmd/api/main.go", imports)
	if len(routes) < 2 {
		t.Fatalf("routes: %+v", routes)
	}
	var getPing, postItems bool
	for _, r := range routes {
		if r.Method == "GET" && r.Path == "/ping" {
			getPing = true
		}
		if r.Method == "POST" && strings.Contains(r.Path, "items") {
			postItems = true
		}
	}
	if !getPing || !postItems {
		t.Fatalf("expected GET /ping and POST ...items, got %+v", routes)
	}
}

func TestExtractRoutesStdlibHandleFunc(t *testing.T) {
	t.Parallel()
	src := `package main

import "net/http"

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {})
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	imports := collectImports(f)
	routes := extractRoutes(f, fset, "main.go", imports)
	var found bool
	for _, r := range routes {
		if r.Path == "/health" && (r.Method == "ANY" || r.Method == "GET") {
			found = true
		}
	}
	if !found {
		t.Fatalf("routes: %+v", routes)
	}
}

func TestFlowGraphToMermaid(t *testing.T) {
	t.Parallel()
	g := &FlowGraph{
		Nodes: []FlowNode{
			{ID: "a", Label: "Client", Kind: KindActor},
			{ID: "b", Label: "API", Kind: KindProcess},
		},
		Edges: []FlowEdge{{From: "a", To: "b", Label: "HTTPS"}},
	}
	s := FlowGraphToMermaid(g)
	for _, needle := range []string{"flowchart", "Client", "API", "HTTPS"} {
		if !strings.Contains(s, needle) {
			t.Fatal(s)
		}
	}
}
