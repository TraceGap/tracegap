package repoanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracegap/internal/analyzer"
	"tracegap/internal/parser"
)

func TestAnalyze_WeakSignalNoConfidentEntrypoint(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "ops", "worker.go"), `package ops

import "net/http"

func BusyLoop(client *http.Client) error {
    _, _ = client.Do(nil)
    return nil
}
`)

	audit := analyzer.AuditResult{}
	audit.Roots = []analyzer.RootResult{{
		RootSpan: parser.Span{Name: "unrelated.root"},
	}}
	audit.PrimaryRoot = &audit.Roots[0]

	res, err := Analyze(repo, audit, []parser.Span{{Name: "ok"}})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !res.WeakSignal {
		t.Fatalf("expected weak signal mode")
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected low-confidence fallback candidates")
	}
	for _, c := range res.Candidates {
		if c.Confidence != ConfidenceLow {
			t.Fatalf("expected low confidence candidate in weak mode, got %s", c.Confidence)
		}
		for _, why := range c.Why {
			if why == "On a reachable path from matched entrypoint" {
				t.Fatalf("did not expect reachable-path claim in weak signal mode")
			}
		}
	}
}

func TestAnalyze_DefaultAndMaxCandidateLimits(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "svc", "handler.go"), `package svc

import "context"

type Tracer interface { Start(context.Context, string) (context.Context, any) }

type C struct{}

func CheckoutHandler(ctx context.Context, tracer Tracer, c *C) error {
    _, _ = tracer.Start(ctx, "checkout")
    return A(c)
}

func A(c *C) error { return c.Do() }
func B(c *C) error { return c.Do() }
func Cc(c *C) error { return c.Do() }
func D(c *C) error { return c.Do() }
func E(c *C) error { return c.Do() }

func (c *C) Do() error { return nil }
`)

	audit := analyzer.AuditResult{}
	audit.Roots = []analyzer.RootResult{{
		RootSpan:    parser.Span{Name: "checkout.request"},
		LargestGaps: []analyzer.Gap{{Duration: 300 * time.Millisecond}},
	}}
	audit.PrimaryRoot = &audit.Roots[0]

	res, err := Analyze(repo, audit, []parser.Span{{Name: "ok"}})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(res.Candidates) < 1 {
		t.Fatalf("expected at least one candidate")
	}
	if len(res.Candidates) > maxCandidateCount {
		t.Fatalf("expected max %d candidates, got %d", maxCandidateCount, len(res.Candidates))
	}
}

func TestAnalyze_CheckoutFixture_ErrorAndSuccessModes(t *testing.T) {
	repoPath := filepath.Join("..", "..", "examples", "checkout-go")
	errorTrace := filepath.Join(repoPath, "traces", "checkout-error.json")
	successTrace := filepath.Join(repoPath, "traces", "checkout-success.json")

	errorSpans, _, err := parser.ParseFile(errorTrace)
	if err != nil {
		t.Fatalf("parse error trace failed: %v", err)
	}
	errorAudit := analyzer.Analyze(errorSpans, analyzer.DefaultTimelineWidth)

	errorResult, err := Analyze(repoPath, errorAudit, errorSpans)
	if err != nil {
		t.Fatalf("Analyze error trace failed: %v", err)
	}
	if errorResult.Mode != "error-context" {
		t.Fatalf("expected error-context mode, got %q", errorResult.Mode)
	}
	if len(errorResult.Candidates) == 0 {
		t.Fatalf("expected candidates for error trace")
	}
	if !strings.Contains(errorResult.Candidates[0].FilePath, "internal/payment/client.go") {
		t.Fatalf("expected payment client as top candidate, got %q", errorResult.Candidates[0].FilePath)
	}

	successSpans, _, err := parser.ParseFile(successTrace)
	if err != nil {
		t.Fatalf("parse success trace failed: %v", err)
	}
	successAudit := analyzer.Analyze(successSpans, analyzer.DefaultTimelineWidth)

	successResult, err := Analyze(repoPath, successAudit, successSpans)
	if err != nil {
		t.Fatalf("Analyze success trace failed: %v", err)
	}
	if successResult.Mode != "instrumentation-opportunity" {
		t.Fatalf("expected instrumentation-opportunity mode, got %q", successResult.Mode)
	}
	if len(successResult.Candidates) == 0 {
		t.Fatalf("expected candidates for success trace")
	}
	if !strings.Contains(successResult.Candidates[0].FilePath, "internal/payment/client.go") {
		t.Fatalf("expected payment client as top candidate in success trace, got %q", successResult.Candidates[0].FilePath)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
