package analyze

import (
	"regexp"
	"sort"
	"strings"
)

// GRPCEndpoint is a discovered service/method pair from proto or generated gRPC stubs.
type GRPCEndpoint struct {
	Service string `json:"service"`
	Method  string `json:"method"`
	Source  string `json:"source,omitempty"`
	File    string `json:"file,omitempty"`
}

var (
	reProtoService = regexp.MustCompile(`(?m)^\s*service\s+([A-Za-z0-9_]+)\s*\{`)
	reProtoRPC     = regexp.MustCompile(`(?m)^\s*rpc\s+([A-Za-z0-9_]+)\s*\(`)
	reGrpcHandler  = regexp.MustCompile(`(?m)_([A-Za-z0-9]+)_([A-Za-z0-9]+)_Handler\s*=`)
)

func parseProtoGRPCEndpoints(relPath string, src []byte) []GRPCEndpoint {
	text := string(src)
	services := reProtoService.FindAllStringSubmatch(text, -1)
	rpcs := reProtoRPC.FindAllStringSubmatch(text, -1)
	if len(services) == 0 || len(rpcs) == 0 {
		return nil
	}
	svc := services[0][1]
	out := make([]GRPCEndpoint, 0, len(rpcs))
	for _, m := range rpcs {
		out = append(out, GRPCEndpoint{
			Service: svc,
			Method:  m[1],
			Source:  "proto",
			File:    relPath,
		})
	}
	return out
}

func parseGeneratedGRPCEndpoints(relPath string, src []byte) []GRPCEndpoint {
	matches := reGrpcHandler.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]GRPCEndpoint, 0, len(matches))
	for _, m := range matches {
		out = append(out, GRPCEndpoint{
			Service: m[1],
			Method:  m[2],
			Source:  "go-generated",
			File:    relPath,
		})
	}
	return out
}

func dedupeGRPCEndpoints(in []GRPCEndpoint) []GRPCEndpoint {
	seen := map[string]struct{}{}
	out := make([]GRPCEndpoint, 0, len(in))
	for _, e := range in {
		svc := strings.TrimSpace(e.Service)
		mth := strings.TrimSpace(e.Method)
		if svc == "" || mth == "" {
			continue
		}
		key := svc + "/" + mth
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, GRPCEndpoint{Service: svc, Method: mth, Source: e.Source, File: e.File})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service == out[j].Service {
			return out[i].Method < out[j].Method
		}
		return out[i].Service < out[j].Service
	})
	return out
}

