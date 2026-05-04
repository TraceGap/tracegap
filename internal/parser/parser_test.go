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

func TestParseFile_DatadogMixedTopLevelArrayParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed-datadog.json")
	data := []byte(`[
	  [
	    {"trace_id":"123","span_id":"1","parent_id":"0","name":"checkout.request","start":1700000000000000,"duration":1000},
	    {"trace_id":"123","span_id":"2","parent_id":"1","name":"auth","start":1700000000000100,"duration":200}
	  ],
	  {"meta":"ignored"}
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestParseFile_DatadogFlatTopLevelArrayParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flat-datadog.json")
	data := []byte(`[
	  {"trace_id":"123","span_id":"1","parent_id":"0","name":"signup.request","start":1700000000000000,"duration":1000},
	  {"trace_id":"123","span_id":"2","parent_id":"1","name":"signup.db","start":1700000000000100,"duration":200},
	  {"trace_id":"123","span_id":"3","parent_id":"1","name":"signup.mail","start":1700000000000200,"duration":200}
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 3 {
		t.Fatalf("expected 3 spans, got %d", len(spans))
	}
}

func TestParseFile_DatadogNestedArrayStillParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested-datadog.json")
	data := []byte(`[
	  [
	    {"trace_id":"x","span_id":"11","parent_id":"0","name":"stream.consume","start":1700000001000000,"duration":500},
	    {"trace_id":"x","span_id":"12","parent_id":"11","name":"stream.handle","start":1700000001000100,"duration":200}
	  ]
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestParseFile_DatadogParentIDNullTreatedAsRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "null-parent-datadog.json")
	data := []byte(`[
	  {"trace_id":"123","span_id":"1","parent_id":null,"name":"signup.request","start":1700000000000000,"duration":1000},
	  {"trace_id":"123","span_id":"2","parent_id":"1","name":"signup.db","start":1700000000000100,"duration":200}
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	if spans[0].ID == "1" && spans[0].ParentID != "" {
		t.Fatalf("expected null parent_id to be treated as root, got %q", spans[0].ParentID)
	}
	foundRoot := false
	for _, sp := range spans {
		if sp.ID == "1" {
			foundRoot = true
			if sp.ParentID != "" {
				t.Fatalf("expected root parent to be empty, got %q", sp.ParentID)
			}
		}
	}
	if !foundRoot {
		t.Fatalf("expected to find span id 1")
	}
}

func TestParseFile_DatadogStringAndNumericIDsBothParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed-id-types-datadog.json")
	data := []byte(`[
	  {"trace_id":999,"span_id":1,"parent_id":0,"name":"signup.request","start":1700000000000000,"duration":1000},
	  {"trace_id":"999","span_id":"2","parent_id":1,"name":"signup.child","start":1700000000000100,"duration":200}
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	ids := map[string]bool{}
	for _, sp := range spans {
		ids[sp.ID] = true
	}
	if !ids["1"] || !ids["2"] {
		t.Fatalf("expected ids 1 and 2, got %+v", ids)
	}
}

func TestParseFile_DatadogTopLevelMultipleValidArrays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi-datadog.json")
	data := []byte(`[
	  [{"trace_id":"t1","span_id":"1","parent_id":"0","name":"root1","start":1700000000000000,"duration":500}],
	  [{"trace_id":"t2","span_id":"3","parent_id":"0","name":"root2","start":1700000001000000,"duration":500}]
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestParseFile_DatadogMixedInvalidAndValidElements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed-elements-datadog.json")
	data := []byte(`[
	  "noise",
	  123,
	  {"not":"a trace"},
	  [
	    {"trace_id":"x","span_id":"10","parent_id":"0","name":"root","start":1700000000000000,"duration":1000},
	    {"trace_id":"x","span_id":"11","parent_id":"10","name":"child","start":1700000000000100,"duration":200}
	  ],
	  [{"foo":"bar"}]
	]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	spans, schema, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if schema != SchemaDatadog {
		t.Fatalf("expected datadog schema, got %s", schema)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans from valid element, got %d", len(spans))
	}
}
