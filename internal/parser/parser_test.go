package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_OTelLikeFixture(t *testing.T) {
	path := filepath.Join("testdata", "trace.json")
	spans, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if len(spans) != 3 {
		t.Fatalf("expected 3 spans, got %d", len(spans))
	}

	foundRoot := false
	for _, s := range spans {
		if s.ID == "root1" {
			foundRoot = true
			if !s.HasTimestamps() {
				t.Fatalf("expected root to have timestamps")
			}
		}
	}
	if !foundRoot {
		t.Fatalf("expected root span root1 to exist")
	}
}

func TestParseFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not-json}"), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatalf("expected parse error for invalid json")
	}
}

func TestParseFile_DedupesSpanIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dup.json")
	data := []byte(`{
  "spans": [
    {"spanId":"dup","name":"one","startTimeUnixNano":"0","endTimeUnixNano":"100"},
    {"spanId":"dup","name":"two","startTimeUnixNano":"0","endTimeUnixNano":"100"},
    {"spanId":"unique","name":"three","startTimeUnixNano":"0","endTimeUnixNano":"100"}
  ]
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 unique spans, got %d", len(spans))
	}
}
