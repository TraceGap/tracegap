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

	m := MatchRootSpan("checkout.request", graph)
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

	m := MatchRootSpan("checkout.request", graph)
	if m.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence, got %s", m.Confidence)
	}
}
