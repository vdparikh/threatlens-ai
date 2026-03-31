package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vdparikh/ThreatLensAI/engine/internal/config"
)

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func TestBuildSystemModelRespectsExclude(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := writeFile(filepath.Join(root, "a.py"), "x"); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "node_modules", "pkg")
	if err := writeFile(filepath.Join(nested, "bad.js"), "x"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Root:              root,
		ExcludePaths:      config.DefaultExcludePaths,
		IncludeExtensions: config.DefaultIncludeExtensions,
		MaxFiles:          10_000,
		MaxFileBytes:      512 * 1024,
	}
	m, err := BuildSystemModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]struct{}{}
	for _, f := range m.Files {
		paths[f.Path] = struct{}{}
	}
	if _, ok := paths["a.py"]; !ok {
		t.Fatal("expected a.py")
	}
	for p := range paths {
		if filepath.HasPrefix(p, "node_modules") {
			t.Fatalf("did not expect path under node_modules: %s", p)
		}
	}
}

func TestMaxFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		name := filepath.Join(root, fmt.Sprintf("f%d.py", i))
		if err := writeFile(name, "#"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{
		Root:              root,
		ExcludePaths:      config.DefaultExcludePaths,
		IncludeExtensions: config.DefaultIncludeExtensions,
		MaxFiles:          2,
		MaxFileBytes:      512 * 1024,
	}
	m, err := BuildSystemModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.FileCount != 2 {
		t.Fatalf("file_count: got %d want 2", m.FileCount)
	}
	if !m.Truncated {
		t.Fatal("expected truncated")
	}
}

func TestGoFileParsesImports(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := `package main

import (
	"fmt"
	"net/http"
)
`
	if err := writeFile(filepath.Join(root, "main.go"), src); err != nil {
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
	if len(m.Files) != 1 {
		t.Fatalf("files: %d", len(m.Files))
	}
	f := m.Files[0]
	if f.Go == nil {
		t.Fatal("expected Go metadata")
	}
	if f.Go.Package != "main" {
		t.Fatalf("package: %q", f.Go.Package)
	}
	if len(f.Go.Imports) != 2 {
		t.Fatalf("imports: %v", f.Go.Imports)
	}
}

func TestLanguageDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ext  string
		want string
	}{
		{".go", "go"},
		{".ts", "typescript"},
		{".tf", "terraform"},
		{".proto", "proto"},
	}
	for _, tt := range tests {
		if got := detectLanguage(tt.ext); got != tt.want {
			t.Fatalf("%s: got %q want %q", tt.ext, got, tt.want)
		}
	}
}
