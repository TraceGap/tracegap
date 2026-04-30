package matcher

import (
	"testing"

	"tracegap/internal/codegraph"
)

func TestMatchRootSpan_PrefersHandlerCandidate(t *testing.T) {
	graph := &codegraph.Graph{
		Functions: map[codegraph.FunctionID]*codegraph.FunctionNode{
			"a": {ID: "a", Package: "checkout", FilePath: "internal/checkout/handler.go", FuncName: "SubmitOrderHandler"},
			"b": {ID: "b", Package: "inventory", FilePath: "internal/inventory/repo.go", FuncName: "Save"},
		},
	}

	m := MatchRootSpan("checkout.request", []string{"auth", "inventory"}, graph)
	if m.FunctionID != "a" {
		t.Fatalf("expected handler match, got %s", m.FunctionID)
	}
	if m.Confidence == ConfidenceLow {
		t.Fatalf("expected non-low confidence for handler match")
	}
}

func TestMatchRootSpan_LowConfidenceWhenNoOverlap(t *testing.T) {
	graph := &codegraph.Graph{
		Functions: map[codegraph.FunctionID]*codegraph.FunctionNode{
			"a": {ID: "a", Package: "alpha", FilePath: "internal/alpha/work.go", FuncName: "DoWork"},
		},
	}

	m := MatchRootSpan("checkout.request", nil, graph)
	if m.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence, got %s", m.Confidence)
	}
}

func TestMatchRootSpan_PenalizesChildSpanSemanticFunctions(t *testing.T) {
	graph := &codegraph.Graph{
		Functions: map[codegraph.FunctionID]*codegraph.FunctionNode{
			"entry":  {ID: "entry", Package: "checkout", FilePath: "internal/checkout/controller.go", FuncName: "CheckoutController"},
			"childy": {ID: "childy", Package: "inventory", FilePath: "internal/inventory/service.go", FuncName: "Reserve"},
		},
	}

	m := MatchRootSpan("checkout.request", []string{"inventory", "reserve"}, graph)
	if m.FunctionID != "entry" {
		t.Fatalf("expected root entrypoint candidate, got %s", m.FunctionID)
	}
}

func TestMatchRootSpan_HTTPHandlerSignatureBoost(t *testing.T) {
	graph := &codegraph.Graph{
		Functions: map[codegraph.FunctionID]*codegraph.FunctionNode{
			"a": {ID: "a", Package: "api", FilePath: "internal/api/handler.go", FuncName: "HandleCheckout", IsHTTPHandler: true},
			"b": {ID: "b", Package: "checkout", FilePath: "internal/checkout/orchestrator.go", FuncName: "RunCheckout"},
		},
	}
	m := MatchRootSpan("checkout.request", nil, graph)
	if m.FunctionID != "a" {
		t.Fatalf("expected http handler candidate to win, got %s", m.FunctionID)
	}
}
