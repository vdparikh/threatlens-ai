package analyze

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// detectGoASTSignals runs deterministic checks that need go/ast (and regex helpers).
func detectGoASTSignals(relPath string, src []byte, routes []RouteEntry) []SecuritySignal {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
	if err != nil {
		return nil
	}
	var out []SecuritySignal
	out = append(out, detectHardcodedJWTSecret(relPath, f)...)
	out = append(out, detectMissingGRPCAuthInterceptor(relPath, f)...)
	out = append(out, detectUnvalidatedProtoFields(relPath, f)...)
	out = append(out, detectSQLStringConcatenation(relPath, f)...)
	out = append(out, detectInsecureTLSMinVersion(relPath, f, src)...)
	out = append(out, detectWorldReadableKeyFile(relPath, src)...)
	out = append(out, detectHTTPAdminNoAuth(relPath, src, routes)...)
	return dedupeSignalsByIDPath(out)
}

var (
	reJWTAssignName = regexp.MustCompile(`(?i)^(jwt|jws|signing|hmac|token).*(secret|key)$|^(jwtsecret|signingkey|hmacsecret|jwtsigningkey|tokensigningkey)$`)
	reSQLInString   = regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|INTO|FROM|WHERE|JOIN)\b`)
	reBadTLSMinVer  = regexp.MustCompile(`MinVersion\s*:\s*(?:tls\.)?(?:VersionSSL30|VersionTLS10|VersionTLS11)\b`)
	reBadTLSMinHex  = regexp.MustCompile(`MinVersion\s*:\s*0x0?30[12]\b`)
	reKeyPathOpen   = regexp.MustCompile(`os\.(?:Open|OpenFile)\(\s*("(?:[^"\\]|\\.)*")`)
)

func dedupeSignalsByIDPath(in []SecuritySignal) []SecuritySignal {
	seen := make(map[string]struct{}, len(in))
	var out []SecuritySignal
	for _, s := range in {
		k := s.ID + "\x00" + s.Path
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

func detectHardcodedJWTSecret(relPath string, f *ast.File) []SecuritySignal {
	var out []SecuritySignal
	add := func() {
		out = append(out, SecuritySignal{
			ID:       "hardcoded-jwt-secret",
			Path:     relPath,
			Severity: "HIGH",
			Summary:  "Literal string assigned to a JWT/signing/HMAC key variable; load secrets from env or a secret manager.",
		})
	}

	checkLit := func(name string, lit *ast.BasicLit) {
		if lit.Kind != token.STRING {
			return
		}
		if !reJWTAssignName.MatchString(name) {
			return
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil || len(s) < 12 {
			return
		}
		add()
	}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if len(vs.Values) == 0 {
				continue
			}
			for i, name := range vs.Names {
				if name.Name == "_" {
					continue
				}
				vi := i
				if len(vs.Values) == 1 {
					vi = 0
				}
				if vi >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[vi].(*ast.BasicLit); ok {
					checkLit(name.Name, lit)
				}
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			if i >= len(as.Rhs) {
				continue
			}
			if lit, ok := as.Rhs[i].(*ast.BasicLit); ok {
				checkLit(id.Name, lit)
			}
		}
		return true
	})
	return dedupeSignalsByIDPath(out)
}

func grpcImportName(f *ast.File) string {
	for _, im := range f.Imports {
		if im.Path == nil {
			continue
		}
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil || path != "google.golang.org/grpc" {
			continue
		}
		if im.Name != nil {
			return im.Name.Name
		}
		return "grpc"
	}
	return ""
}

func callIsGRPCNewServer(call *ast.CallExpr, grpcName string) bool {
	if grpcName == "" {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != grpcName {
		return false
	}
	return sel.Sel.Name == "NewServer"
}

func callIsGRPCInterceptorOption(call *ast.CallExpr, grpcName string) bool {
	if grpcName == "" {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != grpcName {
		return false
	}
	switch sel.Sel.Name {
	case "UnaryInterceptor", "ChainUnaryInterceptor", "StreamInterceptor", "ChainStreamInterceptor":
		return true
	default:
		return false
	}
}

func detectMissingGRPCAuthInterceptor(relPath string, f *ast.File) []SecuritySignal {
	gname := grpcImportName(f)
	if gname == "" {
		return nil
	}
	var hit bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !callIsGRPCNewServer(call, gname) {
			return true
		}
		hasInterceptor := false
		for _, arg := range call.Args {
			ce, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			if callIsGRPCInterceptorOption(ce, gname) {
				hasInterceptor = true
				break
			}
		}
		if !hasInterceptor {
			hit = true
		}
		return true
	})
	if !hit {
		return nil
	}
	return []SecuritySignal{{
		ID:       "missing-grpc-auth-interceptor",
		Path:     relPath,
		Severity: "MEDIUM",
		Summary:  "gRPC grpc.NewServer has no unary/stream interceptor in the option list; add authentication/authorization interceptors (and avoid shipping without any interceptor chain).",
	}}
}

func fileImportsProtobuf(f *ast.File) bool {
	for _, im := range f.Imports {
		if im.Path == nil {
			continue
		}
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		if strings.Contains(p, "google.golang.org/protobuf") ||
			strings.Contains(p, "github.com/golang/protobuf") {
			return true
		}
	}
	return false
}

func typeLooksLikeProtoMessage(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	// Heuristic: generated pb packages are often named pb, v1, apipb, etc.
	if strings.HasSuffix(strings.ToLower(pkg.Name), "pb") {
		return true
	}
	if strings.Contains(strings.ToLower(sel.Sel.Name), "request") ||
		strings.Contains(strings.ToLower(sel.Sel.Name), "message") {
		return true
	}
	return false
}

func funcBodyCallsValidate(body *ast.BlockStmt, paramNames map[string]struct{}) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := fun.X.(*ast.Ident); ok {
				if _, ok := paramNames[id.Name]; ok && fun.Sel.Name == "Validate" {
					found = true
					return false
				}
			}
		case *ast.Ident:
			if fun.Name == "Validate" && len(call.Args) > 0 {
				if id, ok := call.Args[0].(*ast.Ident); ok {
					if _, ok := paramNames[id.Name]; ok {
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

func funcBodyUsesProtoGetters(body *ast.BlockStmt, paramNames map[string]struct{}) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if _, ok := paramNames[id.Name]; ok && strings.HasPrefix(sel.Sel.Name, "Get") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func fileImportsGRPC(f *ast.File) bool {
	for _, im := range f.Imports {
		if im.Path == nil {
			continue
		}
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		if strings.Contains(p, "google.golang.org/grpc") {
			return true
		}
	}
	return false
}

func detectUnvalidatedProtoFields(relPath string, f *ast.File) []SecuritySignal {
	if !fileImportsProtobuf(f) || !fileImportsGRPC(f) {
		return nil
	}
	var out []SecuritySignal
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Type.Params == nil {
			continue
		}
		paramNames := make(map[string]struct{})
		for _, field := range fn.Type.Params.List {
			if !typeLooksLikeProtoMessage(field.Type) {
				continue
			}
			for _, n := range field.Names {
				paramNames[n.Name] = struct{}{}
			}
		}
		if len(paramNames) == 0 {
			continue
		}
		if !funcBodyUsesProtoGetters(fn.Body, paramNames) {
			continue
		}
		if funcBodyCallsValidate(fn.Body, paramNames) {
			continue
		}
		out = append(out, SecuritySignal{
			ID:       "unvalidated-proto-fields",
			Path:     relPath,
			Severity: "MEDIUM",
			Summary:  "gRPC/Protobuf handler uses message getters without a Validate() call on the request; confirm required fields and constraints are checked.",
		})
		break // one per file to avoid duplicate cards (no line in SecuritySignal)
	}
	return out
}

func detectSQLStringConcatenation(relPath string, f *ast.File) []SecuritySignal {
	var out []SecuritySignal
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var sprintf bool
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fmt" && sel.Sel.Name == "Sprintf" {
				sprintf = true
			}
		}
		if !sprintf {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && reSQLInString.MatchString(s) {
				out = append(out, SecuritySignal{
					ID:       "sql-string-concatenation",
					Path:     relPath,
					Severity: "HIGH",
					Summary:  "fmt.Sprintf builds a SQL-looking string; use parameterized queries / prepared statements to prevent SQL injection.",
				})
			}
		}
		return true
	})
	// String concatenation building SQL
	ast.Inspect(f, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		if lit, ok := bin.X.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && reSQLInString.MatchString(s) {
				out = append(out, SecuritySignal{
					ID:       "sql-string-concatenation",
					Path:     relPath,
					Severity: "HIGH",
					Summary:  "String concatenation builds a SQL-looking fragment; use parameterized queries instead.",
				})
			}
		}
		return true
	})
	return dedupeSignalsByIDPath(out)
}

func detectInsecureTLSMinVersion(relPath string, f *ast.File, src []byte) []SecuritySignal {
	var out []SecuritySignal
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}
		s := lit.Value
		if s == "0x301" || s == "0x0301" || s == "769" {
			out = append(out, SecuritySignal{
				ID:       "insecure-tls-min-version",
				Path:     relPath,
				Severity: "HIGH",
				Summary:  "tls.Config MinVersion resolves to TLS 1.0 or older; require at least TLS 1.2.",
			})
		}
		if s == "0x302" || s == "0x0302" || s == "770" {
			out = append(out, SecuritySignal{
				ID:       "insecure-tls-min-version",
				Path:     relPath,
				Severity: "HIGH",
				Summary:  "tls.Config MinVersion resolves to TLS 1.1; require at least TLS 1.2.",
			})
		}
		return true
	})
	raw := string(src)
	if strings.Contains(raw, "MinVersion") {
		if reBadTLSMinVer.MatchString(raw) || reBadTLSMinHex.MatchString(raw) {
			out = append(out, SecuritySignal{
				ID:       "insecure-tls-min-version",
				Path:     relPath,
				Severity: "HIGH",
				Summary:  "tls.Config sets MinVersion below TLS 1.2; use tls.VersionTLS12 or higher.",
			})
		}
	}
	return dedupeSignalsByIDPath(out)
}

func detectWorldReadableKeyFile(relPath string, src []byte) []SecuritySignal {
	s := string(src)
	if !strings.Contains(s, "os.Open") && !strings.Contains(s, "os.OpenFile") {
		return nil
	}
	matches := reKeyPathOpen.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		path, err := strconv.Unquote(m[1])
		if err != nil {
			continue
		}
		lp := strings.ToLower(path)
		if strings.HasSuffix(lp, ".pem") || strings.HasSuffix(lp, ".key") ||
			strings.HasSuffix(lp, ".p12") || strings.HasSuffix(lp, ".pfx") {
			return []SecuritySignal{{
				ID:       "world-readable-key-file",
				Path:     relPath,
				Severity: "MEDIUM",
				Summary:  "Key/certificate material opened by path; verify restrictive file permissions and avoid world-readable paths.",
			}}
		}
	}
	return nil
}

func isSensitiveAdminPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if i := strings.Index(path, " "); i >= 0 && len(path) > 0 && path[0] != '/' {
		path = strings.TrimSpace(path[i+1:])
	}
	for _, pref := range []string{"/admin", "/debug", "/metrics"} {
		if path == pref || strings.HasPrefix(path, pref+"/") {
			return pref
		}
	}
	return ""
}

func fileHasHTTPAuthHints(src string) bool {
	hints := []string{
		"Middleware", "AuthMiddleware", "JWT", "Bearer", "RequireAuth", "Authorize",
		"Authenticate", "BasicAuth", "WithAuth", "Authenticator", "Protected(", "auth.",
	}
	for _, h := range hints {
		if strings.Contains(src, h) {
			return true
		}
	}
	return false
}

func detectHTTPAdminNoAuth(relPath string, src []byte, routes []RouteEntry) []SecuritySignal {
	var which string
	for _, r := range routes {
		if r.File != relPath {
			continue
		}
		if w := isSensitiveAdminPath(r.Path); w != "" {
			which = w
			break
		}
	}
	if which == "" {
		return nil
	}
	raw := string(src)
	if fileHasHTTPAuthHints(raw) {
		return nil
	}
	sev := "MEDIUM"
	summary := "HTTP route registered for " + which + " without obvious auth/middleware hints in this file; lock down admin/debug/metrics or document intentional exposure."
	if which == "/metrics" {
		sev = "LOW"
		summary = "HTTP route registered for /metrics without obvious auth in this file; confirm scrape networks are trusted or protect metrics."
	}
	return []SecuritySignal{{
		ID:       "http-admin-no-auth",
		Path:     relPath,
		Severity: sev,
		Summary:  summary,
	}}
}
