package analyze

import (
	"slices"
	"testing"
)

func TestDetectSecuritySignals(t *testing.T) {
	t.Parallel()
	src := []byte(`
if cert == "" || key == "" { return nil }
reflection.Register(gs)
getEnv("HSM_PIN", "1234")
getEnv("HSMAAS_DB_DSN", "user=postgres password=postgres")
md.Get("user")
`)
	sigs := detectSecuritySignals("cmd/hsmaas/main.go", src, nil)
	if len(sigs) < 3 {
		t.Fatalf("expected several signals, got %d", len(sigs))
	}
}

func TestGoSignalLibrary_Table(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		src     string
		routes  []RouteEntry
		wantIDs []string
		skipIDs []string // must not appear
	}{
		{
			name: "hardcoded-jwt-secret",
			src: `package p
var jwtSigningKey = "0123456789abcdef0123456789abcdef"
`,
			wantIDs: []string{"hardcoded-jwt-secret"},
		},
		{
			name: "missing-grpc-auth-interceptor",
			src: `package main
import "google.golang.org/grpc"
func main() { _ = grpc.NewServer() }
`,
			wantIDs: []string{"missing-grpc-auth-interceptor"},
		},
		{
			name: "grpc has interceptor",
			src: `package main
import "google.golang.org/grpc"
func main() { _ = grpc.NewServer(grpc.UnaryInterceptor(nil)) }
`,
			skipIDs: []string{"missing-grpc-auth-interceptor"},
		},
		{
			name: "sql-string-concatenation",
			src: `package p
import "fmt"
func q() string { return fmt.Sprintf("SELECT * FROM t WHERE id = %s", "x") }
`,
			wantIDs: []string{"sql-string-concatenation"},
		},
		{
			name: "insecure-tls-min-version regex",
			src: `package p
import "crypto/tls"
var _ = tls.Config{ MinVersion: tls.VersionTLS10 }
`,
			wantIDs: []string{"insecure-tls-min-version"},
		},
		{
			name: "world-readable-key-file",
			src: `package p
import "os"
func f() { _, _ = os.Open("/etc/ssl/private/server.key") }
`,
			wantIDs: []string{"world-readable-key-file"},
		},
		{
			name: "http-admin-no-auth",
			src: `package p
func main() {}
`,
			routes: []RouteEntry{
				{Method: "GET", Path: "/admin", File: "srv/admin.go", Line: 1, Framework: "chi"},
			},
			wantIDs: []string{"http-admin-no-auth"},
		},
		{
			name: "http-admin skipped when auth hints",
			src: `package p
var _ = AuthMiddleware
func main() {}
`,
			routes: []RouteEntry{
				{Method: "GET", Path: "/admin", File: "srv/admin.go", Line: 1},
			},
			skipIDs: []string{"http-admin-no-auth"},
		},
		{
			name: "unvalidated-proto-fields",
			src: `package p
import (
  "context"
  "google.golang.org/grpc"
  _ "google.golang.org/protobuf/proto"
  v1pb "example.com/api/v1"
)
type Server struct{}
func (s *Server) X(ctx context.Context, req *v1pb.LoginRequest) error {
  _ = req.GetEmail()
  return nil
}
`,
			wantIDs: []string{"unvalidated-proto-fields"},
		},
		{
			name: "proto Validate present",
			src: `package p
import (
  "context"
  "google.golang.org/grpc"
  _ "google.golang.org/protobuf/proto"
  v1pb "example.com/api/v1"
)
type Server struct{}
func (s *Server) X(ctx context.Context, req *v1pb.LoginRequest) error {
  _ = req.GetEmail()
  return req.Validate()
}
`,
			skipIDs: []string{"unvalidated-proto-fields"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := "srv/admin.go"
			if tc.name == "http-admin-no-auth" || tc.name == "http-admin skipped when auth hints" {
				path = "srv/admin.go"
			} else {
				path = "p.go"
			}
			sigs := detectSecuritySignals(path, []byte(tc.src), tc.routes)
			ids := signalIDs(sigs)
			for _, w := range tc.wantIDs {
				if !slices.Contains(ids, w) {
					t.Fatalf("missing signal %q, got %v", w, ids)
				}
			}
			for _, s := range tc.skipIDs {
				if slices.Contains(ids, s) {
					t.Fatalf("unexpected signal %q, got %v", s, ids)
				}
			}
		})
	}
}

func signalIDs(sigs []SecuritySignal) []string {
	var out []string
	for _, s := range sigs {
		out = append(out, s.ID)
	}
	return out
}
