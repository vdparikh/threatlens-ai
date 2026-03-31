package analyze

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// RouteEntry is a best-effort HTTP route registration found in Go source.
type RouteEntry struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Framework string `json:"framework,omitempty"`
}

const maxRouteEntriesPerFile = 256

// extractRoutes walks the AST for common framework patterns.
func extractRoutes(f *ast.File, fset *token.FileSet, relPath string, importPaths []string) []RouteEntry {
	v := routeExtractor{
		fset:         fset,
		relPath:      relPath,
		importPaths:  importPaths,
		out:          nil,
		perFileCap:   maxRouteEntriesPerFile,
	}
	ast.Walk(&v, f)
	return v.out
}

type routeExtractor struct {
	fset         *token.FileSet
	relPath      string
	importPaths  []string
	out          []RouteEntry
	perFileCap   int
}

func (v *routeExtractor) Visit(node ast.Node) ast.Visitor {
	if len(v.out) >= v.perFileCap {
		return nil
	}
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return v
	}
	fw := v.frameworkForFile()
	pos := v.fset.Position(call.Pos())

	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := fun.Sel.Name
		switch name {
		case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "Any":
			if p, ok := stringLitArg(call, 0); ok {
				v.add(RouteEntry{Method: strings.ToUpper(name), Path: p, File: v.relPath, Line: pos.Line, Framework: fw})
			}
		case "HandleFunc", "Handle":
			// net/http and mux
			if p, ok := stringLitArg(call, 0); ok {
				method := "ANY"
				if name == "HandleFunc" && strings.Contains(p, " ") {
					parts := strings.SplitN(p, " ", 2)
					if len(parts) == 2 && len(parts[0]) > 0 && parts[0][0] != '/' {
						method = strings.ToUpper(parts[0])
						p = parts[1]
					}
				}
				v.add(RouteEntry{Method: method, Path: p, File: v.relPath, Line: pos.Line, Framework: fw})
			}
		case "Route":
			// chi: r.Route("/path", fn) — count as mount point
			if p, ok := stringLitArg(call, 0); ok {
				v.add(RouteEntry{Method: "ROUTE", Path: p, File: v.relPath, Line: pos.Line, Framework: "chi"})
			}
		}
	case *ast.Ident:
		if fun.Name == "HandleFunc" || fun.Name == "Handle" {
			if p, ok := stringLitArg(call, 0); ok {
				v.add(RouteEntry{Method: "ANY", Path: p, File: v.relPath, Line: pos.Line, Framework: fw})
			}
		}
	}
	return v
}

func (v *routeExtractor) add(e RouteEntry) {
	if len(v.out) >= v.perFileCap {
		return
	}
	v.out = append(v.out, e)
}

func (v *routeExtractor) frameworkForFile() string {
	for _, path := range v.importPaths {
		switch {
		case strings.Contains(path, "gin-gonic/gin"):
			return "gin"
		case strings.Contains(path, "labstack/echo"):
			return "echo"
		case strings.Contains(path, "go-chi/chi"):
			return "chi"
		case strings.Contains(path, "gofiber/fiber"):
			return "fiber"
		case path == "net/http":
			return "stdlib"
		case strings.Contains(path, "gorilla/mux"):
			return "gorilla/mux"
		}
	}
	return "unknown"
}

func stringLitArg(call *ast.CallExpr, idx int) (string, bool) {
	if idx >= len(call.Args) {
		return "", false
	}
	lit, ok := call.Args[idx].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
