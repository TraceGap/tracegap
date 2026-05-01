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
}

func TestAnalyze_DoesNotFavorChildSpanSemanticCandidate(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/inventory"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error {
	if err := inventory.Reserve(ctx); err != nil {
		return err
	}
	return payment.Charge(ctx)
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "inventory", "service.go"), `package inventory

import "context"

func Reserve(ctx context.Context) error {
	return nil
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "inventory", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "auth", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected candidates")
	}
	if !strings.Contains(res.Candidates[0].FilePath, "internal/payment/client.go") {
		t.Fatalf("expected downstream uninstrumented payment path to rank first, got %q", res.Candidates[0].FilePath)
	}
}

func TestAnalyze_GapAfterChildSuppressesChildCorrelatedCandidate(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/inventory"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error {
	if err := inventory.Reserve(ctx); err != nil {
		return err
	}
	if err := inventory.ClientCall(ctx); err != nil {
		return err
	}
	return payment.Charge(ctx)
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "inventory", "service.go"), `package inventory

import (
	"context"
	"net/http"
)

func Reserve(ctx context.Context) error { return nil }

func ClientCall(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://inventory.local/check", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "auth", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "inventory.reserve", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected candidates")
	}
	if strings.Contains(res.Candidates[0].FilePath, "internal/inventory/") {
		t.Fatalf("expected child-correlated inventory candidate to be suppressed for post-inventory gap, got %q", res.Candidates[0].FilePath)
	}
	if !strings.Contains(res.Candidates[0].FilePath, "internal/payment/client.go") {
		t.Fatalf("expected payment candidate to rank first, got %q", res.Candidates[0].FilePath)
	}
}

func TestAnalyze_MatchedEntrypointExcludedWithWeakEvidence(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/helper"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error {
	helper.BuildContext(ctx)
	return payment.Charge(ctx)
}
`)

	mustWrite(t, filepath.Join(repo, "internal", "helper", "helper.go"), `package helper

import "context"

func BuildContext(ctx context.Context) {}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "auth", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "inventory", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, c := range res.Candidates {
		if strings.Contains(c.FilePath, "internal/checkout/handler.go") {
			t.Fatalf("expected matched entrypoint with weak independent evidence to be excluded")
		}
	}
}

func TestAnalyze_TinyGapsIgnoredWhenDominantGapExists(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error { return payment.Charge(ctx) }
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "auth", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "inventory", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c3", ParentID: "root", Name: "tiny.marker", Start: base.Add(980 * time.Millisecond), End: base.Add(990 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, c := range res.Candidates {
		for _, why := range c.Why {
			if strings.Contains(why, "10ms gap") {
				t.Fatalf("expected tiny 10ms gap evidence to be ignored when dominant gap exists")
			}
		}
	}
}

func TestAnalyze_InternalHelperNotEmittedOnReachabilityOnly(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/helper"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error {
	helper.BuildContext(ctx)
	return payment.Charge(ctx)
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "helper", "helper.go"), `package helper

import "context"

func BuildContext(ctx context.Context) {}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "auth", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "inventory", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, c := range res.Candidates {
		if strings.Contains(c.FilePath, "internal/helper/helper.go") {
			t.Fatalf("expected helper function to be excluded when only reachable and uninstrumented")
		}
	}
}

func TestAnalyze_LargestGapAlignedExternalRanksAboveHelper(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import (
	"context"
	"example.com/x/internal/helper"
	"example.com/x/internal/payment"
)

func CheckoutHandler(ctx context.Context) error {
	helper.BuildContext(ctx)
	return payment.Charge(ctx)
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "helper", "helper.go"), `package helper

import "context"

func BuildContext(ctx context.Context) {}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import (
	"context"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "auth", Start: base, End: base.Add(200 * time.Millisecond), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "inventory", Start: base.Add(400 * time.Millisecond), End: base.Add(700 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(res.Candidates) == 0 {
		t.Fatalf("expected candidates")
	}
	if !strings.Contains(res.Candidates[0].FilePath, "internal/payment/client.go") {
		t.Fatalf("expected largest-gap aligned external operation to rank first, got %q", res.Candidates[0].FilePath)
	}
}

func TestAnalyze_MatchedEntrypointExcludedEvenWithBasicExternalOp(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "api", "handler.go"), `package api

import (
	"context"
	"net/http"
	"example.com/x/internal/payment"
)

func HandleCheckout(ctx context.Context) error {
	_, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://health.local", nil)
	return payment.PostJSON(ctx)
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "gateway.go"), `package payment

import (
	"context"
	"net/http"
)

func PostJSON(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "inventory.reserve", Start: base, End: base.Add(600 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, c := range res.Candidates {
		if strings.Contains(c.FilePath, "internal/api/handler.go") {
			t.Fatalf("expected matched root entrypoint to be excluded by default even with basic external-op signal")
		}
	}
}

func TestAnalyze_ErrorModeFromMetadataTokens(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/x\n")
	mustWrite(t, filepath.Join(repo, "internal", "payment", "gateway.go"), `package payment

import (
	"context"
	"net/http"
)

func PostJSON(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.local/charge", nil)
	_, err := http.DefaultClient.Do(req)
	return err
}
`)

	base := time.Unix(0, 0)
	spans := []parser.Span{
		{ID: "root", Name: "checkout.request", Start: base, End: base.Add(time.Second), HasStart: true, HasEnd: true, MetadataTokens: []string{"status", "500", "error"}},
		{ID: "c1", ParentID: "root", Name: "inventory.reserve", Start: base, End: base.Add(600 * time.Millisecond), HasStart: true, HasEnd: true},
	}
	audit := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)

	res, err := Analyze(repo, audit, spans)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if res.Mode != "error-context" {
		t.Fatalf("expected error-context mode from metadata tokens, got %q", res.Mode)
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
