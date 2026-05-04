package output

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracegap/internal/analyzer"
	"tracegap/internal/parser"
	"tracegap/internal/repoanalysis"
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
		DetectedSchema: "otlp",
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
	if got, want := payload["detectedSchema"], "otlp"; got != want {
		t.Fatalf("detectedSchema: got %v want %v", got, want)
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
		DetectedSchema: "otlp",
		Roots: []analyzer.RootResult{
			{
				RootSpan:            parser.Span{ID: "root1", Name: "checkout.request"},
				RootDuration:        time.Second,
				CoveredDuration:     500 * time.Millisecond,
				GapDuration:         500 * time.Millisecond,
				CoverageRatio:       0.5,
				PositionalAvailable: true,
				MergedIntervals: []analyzer.Interval{
					{StartOffset: 0, EndOffset: 200 * time.Millisecond, SpanName: "auth"},
					{StartOffset: 400 * time.Millisecond, EndOffset: 700 * time.Millisecond, SpanName: "inventory"},
				},
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

func TestPrintAuditText_SeverityFixtures(t *testing.T) {
	t.Setenv("TGAP_ASCII", "1")
	tests := []struct {
		name         string
		coveragePct  int
		goldenFile   string
	}{
		{name: "over-50", coveragePct: 40, goldenFile: "severity_over_50.golden"},
		{name: "25-to-50", coveragePct: 50, goldenFile: "severity_25_to_50.golden"},
		{name: "10-to-25", coveragePct: 80, goldenFile: "severity_10_to_25.golden"},
		{name: "10-or-less", coveragePct: 95, goldenFile: "severity_10_or_less.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := severityFixtureAuditResult(tt.coveragePct)
			var buf bytes.Buffer
			PrintAuditText(&buf, result)

			goldenPath := filepath.Join("testdata", tt.goldenFile)
			wantBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}
			want := string(wantBytes)
			got := buf.String()
			if got != want {
				t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func severityFixtureAuditResult(coveragePct int) analyzer.AuditResult {
	rootDuration := time.Second
	covered := time.Duration(coveragePct) * 10 * time.Millisecond
	gap := rootDuration - covered
	coveredCols := int(math.Round(float64(coveragePct) / 5.0))
	if coveredCols < 0 {
		coveredCols = 0
	}
	if coveredCols > 20 {
		coveredCols = 20
	}

	result := analyzer.AuditResult{
		DetectedSchema: "otlp",
		Roots: []analyzer.RootResult{
			{
				RootSpan:      parser.Span{ID: "root1", Name: "checkout.request"},
				RootDuration:  rootDuration,
				CoveredDuration: covered,
				GapDuration:   gap,
				CoverageRatio: float64(coveragePct) / 100.0,
				Timeline: analyzer.TimelineData{Width: 20, Mask: buildMask(20, [][2]int{{0, coveredCols}})},
			},
		},
	}
	result.PrimaryRoot = &result.Roots[0]
	return result
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

func TestPrintRepoAnalysisText_RendersCandidates(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled: true,
		Mode:    "error-context",
		MatchedRoot: &repoanalysis.MatchedRoot{
			FilePath:   "internal/checkout/handler.go",
			Line:       31,
			Function:   "checkout.SubmitOrderHandler",
			Confidence: repoanalysis.ConfidenceMedium,
		},
		Candidates: []repoanalysis.Candidate{
			{
				FilePath:   "internal/payment/client.go",
				Line:       42,
				Function:   "payment.(*PaymentClient).Charge",
				Confidence: repoanalysis.ConfidenceHigh,
				Why: []string{
					"On a reachable path from checkout.request",
					"No span detected in this function",
				},
				ActionText: "Add or verify instrumentation around payment.Charge()",
			},
		},
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()

	checks := []string{
		"Repo Analysis (Go)",
		"Matched root span:",
		"internal/checkout/handler.go:31",
		"Most suspicious uninstrumented code paths:",
		"internal/payment/client.go:42",
		"Confidence: high",
		"Start here:",
		"Add or verify instrumentation around payment.Charge()",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %q", want, out)
		}
	}
}

func TestPrintRepoAnalysisText_WeakSignalAndNoCandidates(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled:           true,
		Mode:              "instrumentation-opportunity",
		WeakSignal:        true,
		WeakSignalMessage: "Weak signal: no confident root entrypoint match found, so reachable-path claims are intentionally omitted.",
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()
	if !strings.Contains(out, "Likely instrumentation opportunities:") {
		t.Fatalf("expected instrumentation header, got %q", out)
	}
	if !strings.Contains(out, "Weak signal:") {
		t.Fatalf("expected weak signal message, got %q", out)
	}
	if !strings.Contains(out, "No confident candidates found.") {
		t.Fatalf("expected no candidates message, got %q", out)
	}
}

func TestPrintRepoAnalysisText_SuccessModeUsesConsider(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled: true,
		Mode:    "instrumentation-opportunity",
		Candidates: []repoanalysis.Candidate{
			{
				FilePath:    "internal/orders/repo.go",
				Line:        9,
				Function:    "orders.Save",
				Confidence:  repoanalysis.ConfidenceHigh,
				Why:         []string{"No span detected in this function"},
				ActionText:  "Add a span around orders.Save() to improve trace coverage.",
			},
		},
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()
	if !strings.Contains(out, "Repo Analysis (Go)") {
		t.Fatalf("expected go-specific header, got %q", out)
	}
	if !strings.Contains(out, "Likely instrumentation opportunities:") {
		t.Fatalf("expected instrumentation opportunities heading, got %q", out)
	}
	if !strings.Contains(out, "Consider:") {
		t.Fatalf("expected Consider action label, got %q", out)
	}
}

func TestPrintRepoAnalysisText_ErrorModeUsesStartHereOnly(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled: true,
		Mode:    "error-context",
		Candidates: []repoanalysis.Candidate{
			{
				FilePath:   "internal/orders/repo.go",
				Line:       9,
				Function:   "orders.Save",
				Confidence: repoanalysis.ConfidenceHigh,
				Why:        []string{"Contains error handling behavior"},
				ActionText: "Add instrumentation around orders.Save().",
			},
		},
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()
	if !strings.Contains(out, "Most suspicious uninstrumented code paths:") {
		t.Fatalf("expected error-context heading, got %q", out)
	}
	if !strings.Contains(out, "Start here:") {
		t.Fatalf("expected Start here action label, got %q", out)
	}
	if strings.Contains(out, "Likely instrumentation opportunities:") {
		t.Fatalf("did not expect success heading in error mode, got %q", out)
	}
	if strings.Contains(out, "Consider:") {
		t.Fatalf("did not expect Consider label in error mode, got %q", out)
	}
}

func TestPrintRepoAnalysisText_RendersMultipleMatchedRoots(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled: true,
		Mode:    "instrumentation-opportunity",
		MatchedRoots: []repoanalysis.MatchedRoot{
			{FilePath: "internal/api/handler.go", Line: 56, Function: "api.(*Handler).handleCheckout", Confidence: repoanalysis.ConfidenceHigh},
			{FilePath: "internal/stream/consumer.go", Line: 21, Function: "stream.(*Consumer).consume", Confidence: repoanalysis.ConfidenceMedium},
		},
		Candidates: []repoanalysis.Candidate{{
			FilePath: "internal/payment/gateway.go", Line: 21, Function: "payment.(*HTTPTransport).PostJSON", Confidence: repoanalysis.ConfidenceHigh,
			Why: []string{"No span detected in this function"}, ActionText: "Add a span around payment.(*HTTPTransport).PostJSON() to improve trace coverage.",
		}},
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()
	for _, want := range []string{
		"Matched root spans:",
		"1. internal/api/handler.go:56",
		"2. internal/stream/consumer.go:21",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %q", want, out)
		}
	}
}

func TestPrintRepoAnalysisText_AsyncFlowSections(t *testing.T) {
	result := &repoanalysis.Result{
		Enabled:         true,
		Mode:            "error-context",
		AsyncDetected:   true,
		AsyncWarning:    "Async execution detected across multiple services",
		CorrelationHints: []string{"Shared identifiers between \"signup.request\" and \"stream.consume\": requestid123"},
		PrimaryFlow: &repoanalysis.FlowResult{
			RootSpanName: "signup.request",
			MatchedRoot: &repoanalysis.MatchedRoot{FilePath: "internal/api/handler.go", Line: 56, Function: "api.(*Handler).handleSignup", Confidence: repoanalysis.ConfidenceHigh},
			Candidates: []repoanalysis.Candidate{{
				FilePath: "internal/payment/gateway.go", Line: 21, Function: "payment.(*HTTPTransport).PostJSON", Confidence: repoanalysis.ConfidenceHigh,
				Why: []string{"No span detected in this function"}, ActionText: "Add or verify instrumentation around payment.(*HTTPTransport).PostJSON()",
			}},
		},
		AsyncFlows: []repoanalysis.FlowResult{{
			RootSpanName: "stream.consume",
			MatchedRoot: &repoanalysis.MatchedRoot{FilePath: "internal/stream/consumer.go", Line: 21, Function: "stream.(*Consumer).consume", Confidence: repoanalysis.ConfidenceMedium},
		}},
	}

	var buf bytes.Buffer
	PrintRepoAnalysisText(&buf, result)
	out := buf.String()
	for _, want := range []string{
		"Async execution detected across multiple services",
		"Primary flow:",
		"Async flow 1:",
		"Root span: signup.request",
		"Root span: stream.consume",
		"Correlation hints:",
		"Most suspicious uninstrumented code paths:",
		"Start here:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %q", want, out)
		}
	}
}
