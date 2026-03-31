package analyze

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vdparikh/ThreatLensAI/engine/internal/config"
)

// errStopWalk stops filepath.WalkDir without treating it as a failure.
var errStopWalk = errors.New("stop walk")

func segmentExcluded(rel string, exclude map[string]struct{}) bool {
	rel = filepath.ToSlash(rel)
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		if _, ok := exclude[part]; ok {
			return true
		}
	}
	return false
}

func extAllowed(ext string, allowed map[string]struct{}) bool {
	_, ok := allowed[strings.ToLower(ext)]
	return ok
}

func buildExtSet(inc []string) map[string]struct{} {
	m := make(map[string]struct{}, len(inc))
	for _, e := range inc {
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		m[strings.ToLower(e)] = struct{}{}
	}
	return m
}

func excludeSet(paths []string) map[string]struct{} {
	m := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		m[p] = struct{}{}
	}
	return m
}

// BuildSystemModel walks cfg.Root and returns a model for threat generation.
func BuildSystemModel(cfg config.Config) (*SystemModel, error) {
	st, err := os.Stat(cfg.Root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fs.ErrInvalid
	}

	excl := excludeSet(cfg.ExcludePaths)
	exts := buildExtSet(cfg.IncludeExtensions)

	langs := make(map[string]int)
	var files []FileEntry
	var total int64
	truncated := false

	var allRoutes []RouteEntry
	allGoImports := make(map[string]struct{})
	var grpcCodegenFile bool
	var grpcEndpoints []GRPCEndpoint
	var signals []SecuritySignal

	err = filepath.WalkDir(cfg.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(cfg.Root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if segmentExcluded(rel, excl) {
				return filepath.SkipDir
			}
			return nil
		}
		if segmentExcluded(rel, excl) {
			return nil
		}
		if len(files) >= cfg.MaxFiles {
			truncated = true
			return errStopWalk
		}
		ext := filepath.Ext(d.Name())
		if !extAllowed(ext, exts) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		size := info.Size()
		if size > cfg.MaxFileBytes {
			return nil
		}
		lang := detectLanguage(ext)
		langs[lang]++

		entry := FileEntry{
			Path:     filepath.ToSlash(rel),
			Language: lang,
			Bytes:    size,
		}
		if lang == "go" {
			b, err := os.ReadFile(path)
			if err == nil {
				relSlash := filepath.ToSlash(rel)
				var fileRoutes []RouteEntry
				if g, routes, err := analyzeGoSource(b, relSlash); err == nil {
					entry.Go = g
					allRoutes = append(allRoutes, routes...)
					fileRoutes = routes
					for _, im := range g.Imports {
						allGoImports[im] = struct{}{}
					}
					if strings.HasSuffix(relSlash, "_grpc.pb.go") {
						grpcCodegenFile = true
						grpcEndpoints = append(grpcEndpoints, parseGeneratedGRPCEndpoints(relSlash, b)...)
					}
				}
				signals = append(signals, detectSecuritySignals(relSlash, b, fileRoutes)...)
			}
		}
		if strings.EqualFold(ext, ".proto") {
			b, err := os.ReadFile(path)
			if err == nil {
				relSlash := filepath.ToSlash(rel)
				grpcEndpoints = append(grpcEndpoints, parseProtoGRPCEndpoints(relSlash, b)...)
			}
		}
		files = append(files, entry)
		total += size
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return nil, err
	}

	m := &SystemModel{
		Version:         2,
		Root:            cfg.Root,
		FileCount:       len(files),
		TotalBytes:      total,
		Languages:       langs,
		Files:           files,
		Truncated:       truncated,
		SecuritySignals: signals,
	}

	grpcEndpoints = dedupeGRPCEndpoints(grpcEndpoints)
	if len(allRoutes) > 0 || len(allGoImports) > 0 || grpcCodegenFile || len(grpcEndpoints) > 0 {
		summary, graph := buildGoSummaryAndGraph(allRoutes, allGoImports, grpcCodegenFile, grpcEndpoints)
		m.GoSummary = summary
		m.FlowGraph = graph
		m.MermaidFlow = FlowGraphToMermaid(graph)
		routesOut := allRoutes
		m.RoutesTruncated = len(routesOut) > maxHTTPRoutesInJSON
		if len(routesOut) > maxHTTPRoutesInJSON {
			routesOut = routesOut[:maxHTTPRoutesInJSON]
		}
		m.HTTPRoutes = routesOut
		m.GRPCEndpoints = grpcEndpoints
	}

	return m, nil
}

// maxHTTPRoutesInJSON caps route rows in exported JSON to keep MCP payloads usable.
const maxHTTPRoutesInJSON = 800
