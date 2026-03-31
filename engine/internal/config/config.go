package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Defaults align with the former Python engine and .threatlensai.json.example.
var DefaultExcludePaths = []string{
	"node_modules",
	"dist",
	"build",
	".git",
	".venv",
	"venv",
	"__pycache__",
	".pytest_cache",
	"coverage",
	"target",
	"vendor",
	".next",
}

var DefaultIncludeExtensions = []string{
	".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".rb",
	".tf", ".yaml", ".yml", ".json", ".md", ".proto",
}

// Config is the subset of .threatlensai.json consumed by the engine.
type Config struct {
	Root              string
	ExcludePaths      []string
	IncludeExtensions []string
	MaxFiles          int
	MaxFileBytes      int64
}

// FromRoot loads optional <root>/.threatlensai.json and returns a validated Config.
func FromRoot(root string) (Config, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Config{}, err
	}
	data := map[string]any{}
	path := filepath.Join(abs, ".threatlensai.json")
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &data); err != nil {
			return Config{}, fmt.Errorf("parse .threatlensai.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	return FromMap(abs, data)
}

// FromJSONFile loads config JSON from an arbitrary path; root is the project root for analysis.
func FromJSONFile(root, configPath string) (Config, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Config{}, err
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, err
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return FromMap(abs, data)
}

// FromMap builds Config from a JSON object (for tests).
func FromMap(absRoot string, data map[string]any) (Config, error) {
	cfg := Config{
		Root:              absRoot,
		ExcludePaths:      append([]string(nil), DefaultExcludePaths...),
		IncludeExtensions: append([]string(nil), DefaultIncludeExtensions...),
		MaxFiles:          10_000,
		MaxFileBytes:      512 * 1024,
	}
	if v, ok := data["exclude_paths"]; ok && v != nil {
		if arr, ok := v.([]any); ok {
			cfg.ExcludePaths = stringSlice(arr)
		}
	}
	if v, ok := data["include_extensions"]; ok && v != nil {
		if arr, ok := v.([]any); ok {
			cfg.IncludeExtensions = stringSlice(arr)
		}
	}
	if v, ok := data["max_files"]; ok {
		f, err := toFloat(v)
		if err != nil {
			return Config{}, err
		}
		cfg.MaxFiles = int(f)
	}
	if v, ok := data["max_file_bytes"]; ok {
		f, err := toFloat(v)
		if err != nil {
			return Config{}, err
		}
		cfg.MaxFileBytes = int64(f)
	}
	if cfg.MaxFiles < 1 || cfg.MaxFiles > 1_000_000 {
		return Config{}, errors.New("max_files must be between 1 and 1000000")
	}
	if cfg.MaxFileBytes < 1024 || cfg.MaxFileBytes > 10*1024*1024 {
		return Config{}, errors.New("max_file_bytes out of bounds")
	}
	return cfg, nil
}

func stringSlice(arr []any) []string {
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toFloat(v any) (float64, error) {
	switch t := v.(type) {
	case float64:
		return t, nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	default:
		return 0, fmt.Errorf("expected number, got %T", v)
	}
}
