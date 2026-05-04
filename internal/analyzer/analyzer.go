package analyzer

import (
	"sort"
	"strings"
	"time"

	"tracegap/internal/parser"
)

const (
	DefaultTimelineWidth = 80
	MaxLargestGaps       = 5
	MinLabelCandidates   = 2
	MaxLabelCandidates   = 4
	MaxLabelLength       = 12
)

type Interval struct {
	StartOffset time.Duration
	EndOffset   time.Duration
	SpanID      string
	SpanName    string
}

func (i Interval) Duration() time.Duration {
	if i.EndOffset <= i.StartOffset {
		return 0
	}
	return i.EndOffset - i.StartOffset
}

type Gap struct {
	StartOffset time.Duration
	EndOffset   time.Duration
	Duration    time.Duration
	Kind        string
}

type LabelPlacement struct {
	StartCol int
	Text     string
}

type TimelineData struct {
	Width  int
	Mask   []bool
	Labels []LabelPlacement
}

type RootResult struct {
	RootSpan              parser.Span
	RootDuration          time.Duration
	ChildCount            int
	CoveredDuration       time.Duration
	GapDuration           time.Duration
	CoverageRatio         float64
	PositionalAvailable   bool
	AggregateOnly         bool
	AggregateOnlyNote     string
	SkippedChildrenNoTime int
	MergedIntervals       []Interval
	PositionalGaps        []Gap
	LargestGaps           []Gap
	Timeline              TimelineData
	LikelyCauses          []string
	RecommendedChecks     []string
}

type AuditResult struct {
	DetectedSchema string
	Roots          []RootResult
	PrimaryRoot    *RootResult
	AsyncInsight   AsyncInsight
}

func Analyze(spans []parser.Span, width int) AuditResult {
	if width <= 0 {
		width = DefaultTimelineWidth
	}
	if len(spans) == 0 {
		return AuditResult{}
	}

	byID := make(map[string]parser.Span, len(spans))
	childrenByParent := make(map[string][]parser.Span, len(spans))
	for _, s := range spans {
		byID[s.ID] = s
	}
	for _, s := range spans {
		childrenByParent[s.ParentID] = append(childrenByParent[s.ParentID], s)
	}

	roots := findRoots(spans, byID)
	results := make([]RootResult, 0, len(roots))
	for _, root := range roots {
		results = append(results, analyzeRoot(root, childrenByParent[root.ID], width))
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RootDuration > results[j].RootDuration
	})

	result := AuditResult{Roots: results}
	if len(results) > 0 {
		result.PrimaryRoot = &result.Roots[0]
	}
	result.AsyncInsight = detectAsyncInsight(result.Roots)
	return result
}

func findRoots(spans []parser.Span, byID map[string]parser.Span) []parser.Span {
	roots := make([]parser.Span, 0)
	for _, s := range spans {
		if s.ParentID == "" {
			roots = append(roots, s)
			continue
		}
		if _, ok := byID[s.ParentID]; !ok {
			roots = append(roots, s)
		}
	}
	if len(roots) > 0 {
		return roots
	}

	// Fallback for malformed trees with no clear parentless span.
	best := spans[0]
	for _, s := range spans[1:] {
		if s.Duration() > best.Duration() {
			best = s
		}
	}
	return []parser.Span{best}
}

func analyzeRoot(root parser.Span, directChildren []parser.Span, width int) RootResult {
	res := RootResult{
		RootSpan:          root,
		ChildCount:        len(directChildren),
		LikelyCauses:      defaultLikelyCauses(),
		RecommendedChecks: defaultRecommendedChecks(),
	}

	if root.HasTimestamps() {
		res.RootDuration = root.Duration()
	}

	if !root.HasTimestamps() || res.RootDuration <= 0 {
		res.PositionalAvailable = false
		res.AggregateOnly = true
		covered := sumChildDurations(directChildren)
		if res.RootDuration > 0 && covered > res.RootDuration {
			covered = res.RootDuration
		}
		res.CoveredDuration = covered
		if res.RootDuration > 0 && covered <= res.RootDuration {
			res.GapDuration = res.RootDuration - covered
		}
		res.CoverageRatio = ratio(res.CoveredDuration, res.RootDuration)
		res.AggregateOnlyNote = "Positional analysis unavailable due to missing timestamps. Aggregate values are best-effort only."
		if res.GapDuration > 0 {
			res.LargestGaps = []Gap{{Duration: res.GapDuration, Kind: "aggregate_only"}}
		}
		return res
	}

	intervals, skipped := buildChildIntervals(root, directChildren)
	res.SkippedChildrenNoTime = skipped
	merged := mergeIntervals(intervals)
	res.MergedIntervals = merged
	res.CoveredDuration = sumIntervals(merged)
	if res.CoveredDuration > res.RootDuration {
		res.CoveredDuration = res.RootDuration
	}
	res.GapDuration = res.RootDuration - res.CoveredDuration
	res.CoverageRatio = ratio(res.CoveredDuration, res.RootDuration)
	res.PositionalAvailable = true

	positional := extractPositionalGaps(res.RootDuration, merged)
	res.PositionalGaps = positional
	res.LargestGaps = topLargestGaps(positional, MaxLargestGaps)
	res.Timeline = buildTimeline(res.RootDuration, merged, intervals, width)
	return res
}

func sumChildDurations(children []parser.Span) time.Duration {
	var total time.Duration
	for _, child := range children {
		if !child.HasTimestamps() {
			continue
		}
		total += child.Duration()
	}
	return total
}

func buildChildIntervals(root parser.Span, children []parser.Span) ([]Interval, int) {
	intervals := make([]Interval, 0, len(children))
	skipped := 0
	for _, child := range children {
		if !child.HasTimestamps() {
			skipped++
			continue
		}
		start := child.Start
		end := child.End
		if start.Before(root.Start) {
			start = root.Start
		}
		if end.After(root.End) {
			end = root.End
		}
		if !end.After(start) {
			continue
		}
		intervals = append(intervals, Interval{
			StartOffset: start.Sub(root.Start),
			EndOffset:   end.Sub(root.Start),
			SpanID:      child.ID,
			SpanName:    child.Name,
		})
	}
	return intervals, skipped
}

func mergeIntervals(intervals []Interval) []Interval {
	if len(intervals) == 0 {
		return nil
	}
	sorted := make([]Interval, len(intervals))
	copy(sorted, intervals)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].StartOffset == sorted[j].StartOffset {
			return sorted[i].EndOffset < sorted[j].EndOffset
		}
		return sorted[i].StartOffset < sorted[j].StartOffset
	})

	merged := make([]Interval, 0, len(sorted))
	cur := sorted[0]
	for _, next := range sorted[1:] {
		if next.StartOffset <= cur.EndOffset {
			if next.EndOffset > cur.EndOffset {
				cur.EndOffset = next.EndOffset
			}
			continue
		}
		merged = append(merged, cur)
		cur = next
	}
	merged = append(merged, cur)
	return merged
}

func sumIntervals(intervals []Interval) time.Duration {
	var sum time.Duration
	for _, in := range intervals {
		sum += in.Duration()
	}
	return sum
}

func extractPositionalGaps(rootDuration time.Duration, merged []Interval) []Gap {
	if rootDuration <= 0 {
		return nil
	}
	if len(merged) == 0 {
		return []Gap{{StartOffset: 0, EndOffset: rootDuration, Duration: rootDuration, Kind: "full"}}
	}

	gaps := make([]Gap, 0, len(merged)+1)
	first := merged[0]
	if first.StartOffset > 0 {
		gaps = append(gaps, Gap{
			StartOffset: 0,
			EndOffset:   first.StartOffset,
			Duration:    first.StartOffset,
			Kind:        "before_first",
		})
	}

	for i := 1; i < len(merged); i++ {
		prev := merged[i-1]
		next := merged[i]
		if next.StartOffset > prev.EndOffset {
			gaps = append(gaps, Gap{
				StartOffset: prev.EndOffset,
				EndOffset:   next.StartOffset,
				Duration:    next.StartOffset - prev.EndOffset,
				Kind:        "between",
			})
		}
	}

	last := merged[len(merged)-1]
	if last.EndOffset < rootDuration {
		gaps = append(gaps, Gap{
			StartOffset: last.EndOffset,
			EndOffset:   rootDuration,
			Duration:    rootDuration - last.EndOffset,
			Kind:        "after_last",
		})
	}
	return gaps
}

func topLargestGaps(gaps []Gap, max int) []Gap {
	if len(gaps) == 0 {
		return nil
	}
	sorted := make([]Gap, len(gaps))
	copy(sorted, gaps)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Duration == sorted[j].Duration {
			return sorted[i].StartOffset < sorted[j].StartOffset
		}
		return sorted[i].Duration > sorted[j].Duration
	})
	if len(sorted) > max {
		sorted = sorted[:max]
	}
	return sorted
}

func buildTimeline(rootDuration time.Duration, merged []Interval, childIntervals []Interval, width int) TimelineData {
	if width <= 0 {
		width = DefaultTimelineWidth
	}
	mask := make([]bool, width)
	if rootDuration <= 0 {
		return TimelineData{Width: width, Mask: mask}
	}

	for _, in := range merged {
		startCol, endCol := durationRangeToCols(in.StartOffset, in.EndOffset, rootDuration, width)
		for col := startCol; col < endCol && col < width; col++ {
			if col >= 0 {
				mask[col] = true
			}
		}
	}

	labels := placeLabels(mask, childIntervals, rootDuration, width)
	return TimelineData{Width: width, Mask: mask, Labels: labels}
}

func placeLabels(mask []bool, childIntervals []Interval, rootDuration time.Duration, width int) []LabelPlacement {
	if len(childIntervals) < MinLabelCandidates || rootDuration <= 0 || width <= 0 {
		return nil
	}

	candidates := make([]Interval, 0, len(childIntervals))
	for _, in := range childIntervals {
		if in.Duration() > 0 && strings.TrimSpace(in.SpanName) != "" {
			candidates = append(candidates, in)
		}
	}
	if len(candidates) < MinLabelCandidates {
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Duration() > candidates[j].Duration()
	})
	if len(candidates) > MaxLabelCandidates {
		candidates = candidates[:MaxLabelCandidates]
	}

	occupied := make([]bool, width)
	placements := make([]LabelPlacement, 0, len(candidates))
	for _, cand := range candidates {
		startCol, endCol := durationRangeToCols(cand.StartOffset, cand.EndOffset, rootDuration, width)
		spanWidth := endCol - startCol
		if spanWidth <= 0 {
			continue
		}

		label := truncateLabel(cand.SpanName, MaxLabelLength)
		labelRunes := []rune(label)
		if len(labelRunes) == 0 || len(labelRunes) > spanWidth {
			continue
		}

		labelStart := startCol + (spanWidth-len(labelRunes))/2
		labelEnd := labelStart + len(labelRunes)
		if labelStart < startCol || labelEnd > endCol {
			continue
		}

		ok := true
		for col := labelStart; col < labelEnd; col++ {
			if col < 0 || col >= width || occupied[col] || !mask[col] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for col := labelStart; col < labelEnd; col++ {
			occupied[col] = true
		}
		placements = append(placements, LabelPlacement{StartCol: labelStart, Text: string(labelRunes)})
	}

	// If labels are too dense and we could not place at least two, omit all labels.
	if len(placements) < MinLabelCandidates {
		return nil
	}
	return placements
}

func truncateLabel(name string, max int) string {
	label := strings.TrimSpace(name)
	if label == "" {
		return ""
	}
	r := []rune(label)
	if len(r) <= max {
		return label
	}
	return string(r[:max])
}

func durationRangeToCols(start, end, total time.Duration, width int) (int, int) {
	if total <= 0 || width <= 0 {
		return 0, 0
	}
	if end < start {
		return 0, 0
	}
	startF := float64(start) / float64(total)
	endF := float64(end) / float64(total)
	if startF < 0 {
		startF = 0
	}
	if endF > 1 {
		endF = 1
	}
	startCol := int(startF * float64(width))
	endCol := int(endF * float64(width))
	if endCol <= startCol {
		endCol = startCol + 1
	}
	if startCol < 0 {
		startCol = 0
	}
	if endCol > width {
		endCol = width
	}
	return startCol, endCol
}

func ratio(part, total time.Duration) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func defaultLikelyCauses() []string {
	return []string{
		"Likely missing child span around internal work",
		"Possible missing outbound HTTP/gRPC/client span",
		"Possible missing database span",
		"Possible trace context propagation issue",
		"Possible async/background work not linked to parent",
		"Possible middleware/framework time not instrumented",
	}
}

func defaultRecommendedChecks() []string {
	return []string{
		"Add spans around external calls (HTTP, DB, RPC)",
		"Ensure trace context propagation (headers/context)",
		"Inspect retry/backoff or async logic",
		"Check framework/middleware instrumentation",
	}
}
