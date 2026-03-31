package analyze

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// GoDetail is attached to file entries for parsed Go sources.
type GoDetail struct {
	Package string   `json:"package"`
	Imports []string `json:"imports"`
}

// analyzeGoSource parses a full Go file for imports, package name, and HTTP routes.
func analyzeGoSource(src []byte, relPath string) (*GoDetail, []RouteEntry, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil, nil, err
	}
	imports := collectImports(f)
	sort.Strings(imports)
	detail := &GoDetail{
		Package: f.Name.Name,
		Imports: imports,
	}
	routes := extractRoutes(f, fset, relPath, imports)
	return detail, routes, nil
}

func collectImports(f *ast.File) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, im := range f.Imports {
		if im.Path == nil {
			continue
		}
		p := strings.Trim(im.Path.Value, `"`)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
