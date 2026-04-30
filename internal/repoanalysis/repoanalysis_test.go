package repoanalysis

import (
	"os"
	"path/filepath"
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
		RootSpan: parser.Span{Name: "checkout.request"},
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

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
