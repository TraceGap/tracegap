package goast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracegap/internal/codegraph"
)

func TestBuildGraph_ExtractsFunctionsAndSignals(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/test\n")
	mustWrite(t, filepath.Join(repo, "internal", "svc", "handler.go"), `package svc

import (
    "context"
    "database/sql"
    "net/http"
)

type PaymentClient struct{}

func SubmitOrderHandler(ctx context.Context, tracer any, db *sql.DB, client *http.Client, pc *PaymentClient) error {
    _, _ = tracer.(interface{ Start(context.Context, string) (context.Context, any) })
    _, _ = client.Do(nil)
    _, _ = db.QueryContext(ctx, "select 1")
    if err := Charge(pc); err != nil {
        return err
    }
    return nil
}

func Charge(pc *PaymentClient) error {
    return pc.Publish()
}

func (p *PaymentClient) Publish() error {
    return nil
}
`)

	graph, err := BuildGraph(repo, DefaultOptions())
	if err != nil {
		t.Fatalf("BuildGraph failed: %v", err)
	}
	if len(graph.Functions) != 3 {
		t.Fatalf("expected 3 functions, got %d", len(graph.Functions))
	}

	handler := findByName(t, graph, "SubmitOrderHandler")
	if !handler.ExternalOps.HTTP {
		t.Fatalf("expected HTTP external op for handler")
	}
	if !handler.ExternalOps.DB {
		t.Fatalf("expected DB external op for handler")
	}
	if !handler.HandlesError {
		t.Fatalf("expected error handling signal")
	}
	if len(handler.LocalCalls) == 0 {
		t.Fatalf("expected local calls to be resolved")
	}

	charge := findByName(t, graph, "Charge")
	if len(charge.LocalCalls) == 0 {
		t.Fatalf("expected Charge to have local call")
	}
	if !charge.ExternalOps.Queue {
		t.Fatalf("expected Charge() to be treated as queue/event op")
	}

	publish := findByName(t, graph, "Publish")
	if publish.ExternalOps.Queue {
		t.Fatalf("expected Publish() definition itself not to be tagged as queue/event op")
	}
}

func TestBuildGraph_RespectsIgnoreAndFileSize(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/test\n")
	mustWrite(t, filepath.Join(repo, "vendor", "x", "ignored.go"), "package x\nfunc Ignored(){}\n")
	mustWrite(t, filepath.Join(repo, "service", "ok.go"), "package service\nfunc Keep(){}\n")

	bigContent := "package service\n\n" + strings.Repeat("// filler\n", 300000)
	mustWrite(t, filepath.Join(repo, "service", "huge.go"), bigContent)

	opts := DefaultOptions()
	opts.MaxFileSize = 1024

	graph, err := BuildGraph(repo, opts)
	if err != nil {
		t.Fatalf("BuildGraph failed: %v", err)
	}

	if _, ok := graph.ByName["Ignored"]; ok {
		t.Fatalf("expected vendor function to be ignored")
	}
	if _, ok := graph.ByName["Keep"]; !ok {
		t.Fatalf("expected Keep function to be parsed")
	}
}

func TestBuildGraph_ResolvesCrossPackageCalls(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/test\n")
	mustWrite(t, filepath.Join(repo, "internal", "checkout", "handler.go"), `package checkout

import "example.com/test/internal/payment"

func SubmitOrderHandler() error {
    return payment.Charge()
}
`)
	mustWrite(t, filepath.Join(repo, "internal", "payment", "client.go"), `package payment

import "net/http"

func Charge() error {
    _, _ = http.Get("https://payments.internal/charge")
    return nil
}
`)

	graph, err := BuildGraph(repo, DefaultOptions())
	if err != nil {
		t.Fatalf("BuildGraph failed: %v", err)
	}

	handler := findByName(t, graph, "SubmitOrderHandler")
	charge := findByName(t, graph, "Charge")

	found := false
	for _, call := range handler.LocalCalls {
		if call == charge.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected handler to resolve local call to payment.Charge")
	}
}

func TestBuildGraph_AssociatesRouteTokensWithHandler(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/test\n")
	mustWrite(t, filepath.Join(repo, "internal", "api", "routes.go"), `package api

import "net/http"

func RegisterRoutes() {
	http.HandleFunc("/v1/checkout/orders", HandleCheckout)
}

func HandleCheckout(w http.ResponseWriter, r *http.Request) {}
`)

	graph, err := BuildGraph(repo, DefaultOptions())
	if err != nil {
		t.Fatalf("BuildGraph failed: %v", err)
	}
	h := findByName(t, graph, "HandleCheckout")
	if !h.IsHTTPHandler {
		t.Fatalf("expected HTTP handler signature to be detected")
	}
	joined := strings.Join(h.RouteTokens, " ")
	for _, tok := range []string{"v1", "checkout", "orders"} {
		if !strings.Contains(joined, tok) {
			t.Fatalf("expected route token %q in %q", tok, joined)
		}
	}
}

func findByName(t *testing.T, graph *codegraph.Graph, name string) *codegraph.FunctionNode {
	t.Helper()
	ids := graph.ByName[name]
	if len(ids) == 0 {
		t.Fatalf("function %s not found", name)
	}
	return graph.Functions[ids[0]]
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
