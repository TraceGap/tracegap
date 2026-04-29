package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFile_DetectsAndParsesSupportedSchemas(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		wantSchema SchemaType
		wantSpans  int
		wantRootID string
	}{
		{name: "otlp", file: "trace.json", wantSchema: SchemaOTLP, wantSpans: 3, wantRootID: "EEE19B7EC3C1B173"},
		{name: "jaeger", file: "jaeger.json", wantSchema: SchemaJaeger, wantSpans: 3, wantRootID: "eee19b7ec3c1b173"},
		{name: "datadog", file: "datadog.json", wantSchema: SchemaDatadog, wantSpans: 3, wantRootID: "111"},
		{name: "grafana-otlp", file: "grafana_otlp.json", wantSchema: SchemaOTLP, wantSpans: 2, wantRootID: "AAA19B7EC3C1B173"},
		{name: "grafana-jaeger", file: "grafana_jaeger.json", wantSchema: SchemaJaeger, wantSpans: 2, wantRootID: "bbbbbbbbbbbbbbbb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("testdata", tt.file)
			spans, schema, err := ParseFile(path)
			if err != nil {
				t.Fatalf("ParseFile failed: %v", err)
			}
			if schema != tt.wantSchema {
				t.Fatalf("schema: got %s want %s", schema, tt.wantSchema)
			}
			if len(spans) != tt.wantSpans {
				t.Fatalf("expected %d spans, got %d", tt.wantSpans, len(spans))
			}

			foundRoot := false
			for _, s := range spans {
				if s.ID == tt.wantRootID {
					foundRoot = true
					if !s.HasTimestamps() {
						t.Fatalf("expected root to have timestamps")
					}
				}
			}
			if !foundRoot {
				t.Fatalf("expected root span %s to exist", tt.wantRootID)
			}
		})
	}
}

func TestParseFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not-json}"), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if _, _, err := ParseFile(path); err == nil {
		t.Fatalf("expected parse error for invalid json")
	}
}

func TestParseFile_DedupesSpanIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dup.json")
	data := []byte(`{
	"resourceSpans": [
		{
			"scopeSpans": [
				{
					"spans": [
						{"spanId":"dup","name":"one","startTimeUnixNano":"0","endTimeUnixNano":"100"},
						{"spanId":"dup","name":"two","startTimeUnixNano":"0","endTimeUnixNano":"100"},
						{"spanId":"unique","name":"three","startTimeUnixNano":"0","endTimeUnixNano":"100"}
					]
				}
			]
		}
  ]
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaOTLP {
		t.Fatalf("expected OTLP schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 unique spans, got %d", len(spans))
	}
}

func TestParseFile_UnknownSchema(t *testing.T) {
	path := filepath.Join("testdata", "unknown.json")
	_, schema, err := ParseFile(path)
	if err == nil {
		t.Fatalf("expected unsupported schema error")
	}
	if schema != SchemaUnknown {
		t.Fatalf("expected unknown schema, got %s", schema)
	}
	if !strings.Contains(err.Error(), "unsupported trace schema") {
		t.Fatalf("unexpected error: %v", err)
	}
}
