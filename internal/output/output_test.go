package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracegap/internal/analyzer"
	"tracegap/internal/parser"
)

func TestRenderTimeline_ASCIIFallback(t *testing.T) {
	t.Setenv("TGAP_ASCII", "1")
	data := analyzer.TimelineData{
		Width: 4,
		Mask:  []bool{true, false, true, false},
	}
	bar := renderTimeline(data)
	if got, want := bar, "=.=."; got != want {
		t.Fatalf("timeline bar: got %q want %q", got, want)
	}
}

func TestPrintAuditJSON_EmitsSummary(t *testing.T) {
	result := analyzer.AuditResult{
		Roots: []analyzer.RootResult{
			{
				RootSpan:        parser.Span{ID: "r1", Name: "root"},
				RootDuration:    time.Second,
				CoveredDuration: 700 * time.Millisecond,
				GapDuration:     300 * time.Millisecond,
				CoverageRatio:   0.7,
				Timeline:        analyzer.TimelineData{Width: 10, Mask: []bool{true, true, true, true, true, true, true, false, false, false}},
			},
		},
	}
	result.PrimaryRoot = &result.Roots[0]

	var buf bytes.Buffer
	if err := PrintAuditJSON(&buf, result, "trace.json"); err != nil {
		t.Fatalf("PrintAuditJSON failed: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output failed: %v", err)
	}
	if got, want := payload["file"], "trace.json"; got != want {
		t.Fatalf("file field: got %v want %v", got, want)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object")
	}
	if got, want := int(summary["traceCoveragePercent"].(float64)), 70; got != want {
		t.Fatalf("traceCoveragePercent: got %d want %d", got, want)
	}
}

func TestPrintAuditText_PrintsNoSpansWithNilPrimary(t *testing.T) {
	var buf bytes.Buffer
	PrintAuditText(&buf, analyzer.AuditResult{})
	if !strings.Contains(buf.String(), "No spans found in trace file.") {
		t.Fatalf("expected no spans message, got %q", buf.String())
	}
}

func TestSupportsUnicode_ForcedAscii(t *testing.T) {
	if err := os.Setenv("TGAP_ASCII", "1"); err != nil {
		t.Fatalf("setenv failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv("TGAP_ASCII")
	})
	if supportsUnicode() {
		t.Fatalf("expected unicode disabled when TGAP_ASCII=1")
	}
}

func TestPrintAuditText_Golden(t *testing.T) {
	t.Setenv("TGAP_ASCII", "1")
	result := analyzer.AuditResult{
		Roots: []analyzer.RootResult{
			{
				RootSpan:            parser.Span{ID: "root1", Name: "checkout.request"},
				RootDuration:        time.Second,
				CoveredDuration:     500 * time.Millisecond,
				GapDuration:         500 * time.Millisecond,
				CoverageRatio:       0.5,
				PositionalAvailable: true,
				LargestGaps: []analyzer.Gap{
					{StartOffset: 700 * time.Millisecond, EndOffset: time.Second, Duration: 300 * time.Millisecond, Kind: "after_last"},
					{StartOffset: 200 * time.Millisecond, EndOffset: 400 * time.Millisecond, Duration: 200 * time.Millisecond, Kind: "between"},
				},
				LikelyCauses: []string{
					"Likely missing child span around internal work",
					"Possible missing outbound HTTP/gRPC/client span",
					"Possible missing database span",
					"Possible trace context propagation issue",
					"Possible async/background work not linked to parent",
					"Possible middleware/framework time not instrumented",
				},
				RecommendedChecks: []string{
					"Add spans around external calls (HTTP, DB, RPC)",
					"Ensure trace context propagation (headers/context)",
					"Inspect retry/backoff or async logic",
					"Check framework/middleware instrumentation",
				},
				Timeline: analyzer.TimelineData{Width: 80, Mask: buildMask(80, [][2]int{{0, 16}, {32, 56}})},
			},
		},
	}
	result.PrimaryRoot = &result.Roots[0]

	var buf bytes.Buffer
	PrintAuditText(&buf, result)

	goldenPath := filepath.Join("testdata", "audit_text.golden")
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}
	want := string(wantBytes)
	got := buf.String()
	if got != want {
		t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func buildMask(width int, covered [][2]int) []bool {
	mask := make([]bool, width)
	for _, c := range covered {
		start := c[0]
		end := c[1]
		if start < 0 {
			start = 0
		}
		if end > width {
			end = width
		}
		for i := start; i < end; i++ {
			mask[i] = true
		}
	}
	return mask
}
