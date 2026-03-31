package analyze

import (
	"path/filepath"
	"strings"
)

func detectLanguage(ext string) string {
	ext = strings.ToLower(ext)
	switch ext {
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx":
		return "javascript"
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".tf":
		return "terraform"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".md":
		return "markdown"
	case ".proto":
		return "proto"
	default:
		return "other"
	}
}

func normalizeExt(name string) string {
	return strings.ToLower(filepath.Ext(name))
}
