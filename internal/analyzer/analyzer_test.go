package analyzer

import (
	"fmt"
	"testing"
	"time"

	"tracegap/internal/parser"
)

func TestAnalyze_CoverageAndLargestGaps(t *testing.T) {
	rootStart := time.Unix(0, 0)
	rootEnd := time.Unix(0, int64(time.Second))

	spans := []parser.Span{
		{ID: "root1", Name: "checkout.request", Start: rootStart, End: rootEnd, HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root1", Name: "auth", Start: rootStart, End: time.Unix(0, int64(200*time.Millisecond)), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root1", Name: "inventory", Start: time.Unix(0, int64(400*time.Millisecond)), End: time.Unix(0, int64(700*time.Millisecond)), HasStart: true, HasEnd: true},
	}

	result := Analyze(spans, 80)
	if result.PrimaryRoot == nil {
		t.Fatalf("expected primary root")
	}
	root := result.PrimaryRoot
	if got, want := root.CoveredDuration, 500*time.Millisecond; got != want {
		t.Fatalf("covered duration: got %v want %v", got, want)
	}
	if got, want := root.GapDuration, 500*time.Millisecond; got != want {
		t.Fatalf("gap duration: got %v want %v", got, want)
	}
	if len(root.LargestGaps) < 2 {
		t.Fatalf("expected at least 2 gaps, got %d", len(root.LargestGaps))
	}
	if got, want := root.LargestGaps[0].Duration, 300*time.Millisecond; got != want {
		t.Fatalf("largest gap duration: got %v want %v", got, want)
	}
	if got, want := root.LargestGaps[1].Duration, 200*time.Millisecond; got != want {
		t.Fatalf("second gap duration: got %v want %v", got, want)
	}
}

func TestAnalyze_MergesOverlappingIntervals(t *testing.T) {
	rootStart := time.Unix(0, 0)
	rootEnd := time.Unix(0, int64(time.Second))

	spans := []parser.Span{
		{ID: "root", Name: "root", Start: rootStart, End: rootEnd, HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "c1", Start: time.Unix(0, int64(100*time.Millisecond)), End: time.Unix(0, int64(500*time.Millisecond)), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "c2", Start: time.Unix(0, int64(300*time.Millisecond)), End: time.Unix(0, int64(700*time.Millisecond)), HasStart: true, HasEnd: true},
	}

	result := Analyze(spans, 80)
	if result.PrimaryRoot == nil {
		t.Fatalf("expected primary root")
	}
	root := result.PrimaryRoot
	if got, want := root.CoveredDuration, 600*time.Millisecond; got != want {
		t.Fatalf("covered duration: got %v want %v", got, want)
	}
	if got, want := root.GapDuration, 400*time.Millisecond; got != want {
		t.Fatalf("gap duration: got %v want %v", got, want)
	}
	if len(root.MergedIntervals) != 1 {
		t.Fatalf("expected 1 merged interval, got %d", len(root.MergedIntervals))
	}
}

func TestAnalyze_FallbacksToLongestSpanWhenNoRoot(t *testing.T) {
	spans := []parser.Span{
		{ID: "a", ParentID: "b", Name: "a", Start: time.Unix(0, 0), End: time.Unix(0, int64(500*time.Millisecond)), HasStart: true, HasEnd: true},
		{ID: "b", ParentID: "a", Name: "b", Start: time.Unix(0, 0), End: time.Unix(0, int64(900*time.Millisecond)), HasStart: true, HasEnd: true},
	}

	result := Analyze(spans, 80)
	if result.PrimaryRoot == nil {
		t.Fatalf("expected primary root")
	}
	if got, want := result.PrimaryRoot.RootSpan.ID, "b"; got != want {
		t.Fatalf("primary root id: got %q want %q", got, want)
	}
}

func TestAnalyze_SkipsChildrenMissingTimestamps(t *testing.T) {
	rootStart := time.Unix(0, 0)
	rootEnd := time.Unix(0, int64(time.Second))

	spans := []parser.Span{
		{ID: "root", Name: "root", Start: rootStart, End: rootEnd, HasStart: true, HasEnd: true},
		{ID: "c1", ParentID: "root", Name: "timed", Start: rootStart, End: time.Unix(0, int64(200*time.Millisecond)), HasStart: true, HasEnd: true},
		{ID: "c2", ParentID: "root", Name: "untimed", HasStart: false, HasEnd: false},
	}

	result := Analyze(spans, 80)
	if result.PrimaryRoot == nil {
		t.Fatalf("expected primary root")
	}
	if got, want := result.PrimaryRoot.SkippedChildrenNoTime, 1; got != want {
		t.Fatalf("skipped children: got %d want %d", got, want)
	}
	if !result.PrimaryRoot.PositionalAvailable {
		t.Fatalf("expected positional analysis to be available")
	}
}

func BenchmarkAnalyzeDenseOverlaps(b *testing.B) {
	spans := benchmarkSpans(2000, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(spans, 80)
	}
}

func BenchmarkAnalyzeSparseIntervals(b *testing.B) {
	spans := benchmarkSpans(2000, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(spans, 80)
	}
}

func benchmarkSpans(childCount int, overlap bool) []parser.Span {
	rootStart := time.Unix(0, 0)
	rootEnd := time.Unix(0, int64(30*time.Second))
	spans := make([]parser.Span, 0, childCount+1)
	spans = append(spans, parser.Span{ID: "root", Name: "root", Start: rootStart, End: rootEnd, HasStart: true, HasEnd: true})

	step := 10 * time.Millisecond
	dur := 5 * time.Millisecond
	if overlap {
		dur = 25 * time.Millisecond
	}
	for i := 0; i < childCount; i++ {
		start := rootStart.Add(time.Duration(i) * step)
		end := start.Add(dur)
		if end.After(rootEnd) {
			end = rootEnd
		}
		spans = append(spans, parser.Span{
			ID:       fmt.Sprintf("c-%d", i),
			ParentID: "root",
			Name:     "bench",
			Start:    start,
			End:      end,
			HasStart: true,
			HasEnd:   true,
		})
	}
	return spans
}
