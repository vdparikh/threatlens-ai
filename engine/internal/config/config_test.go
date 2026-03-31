package config

import "testing"

func TestFromMapBounds(t *testing.T) {
	t.Parallel()
	_, err := FromMap("/tmp", map[string]any{"max_files": 0})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = FromMap("/tmp", map[string]any{"max_file_bytes": 100})
	if err == nil {
		t.Fatal("expected error")
	}
}
