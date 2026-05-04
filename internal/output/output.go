package output

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"tracegap/internal/analyzer"
	"tracegap/internal/repoanalysis"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

func PrintNoSpans(w io.Writer) {
	fmt.Fprintln(w, "No spans found in trace file.")
}

func PrintAuditText(w io.Writer, result analyzer.AuditResult) {
	if result.PrimaryRoot == nil {
		PrintNoSpans(w)
		return
	}

	primary := result.PrimaryRoot
	coveragePct := percent(primary.CoverageRatio)
	gapPct := 100 - coveragePct

	fmt.Fprintln(w, "TraceGap Audit")
	if result.DetectedSchema != "" {
		fmt.Fprintf(w, "Schema: %s\n", formatSchema(result.DetectedSchema))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Root span: %s (%s)\n", primary.RootSpan.Name, formatDuration(primary.RootDuration))
	fmt.Fprintln(w, severityMessage(gapPct))
	fmt.Fprintf(w, "Trace coverage: %d%%\n", coveragePct)
	fmt.Fprintf(w, "Unaccounted time: %d%% (%s)\n", gapPct, formatDuration(primary.GapDuration))
	if primary.AggregateOnly {
		fmt.Fprintln(w)
		fmt.Fprintln(w, primary.AggregateOnlyNote)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Largest gaps:")
	if len(primary.LargestGaps) == 0 {
		fmt.Fprintln(w, "No significant gaps found.")
	} else {
		for i, gap := range primary.LargestGaps {
			context := describeGapContext(gap, *primary)
			if primary.PositionalAvailable {
				fmt.Fprintf(w, "%d. %s-%s (%s)%s\n", i+1, formatDuration(gap.StartOffset), formatDuration(gap.EndOffset), formatDuration(gap.Duration), context)
			} else {
				fmt.Fprintf(w, "%d. %s (aggregate-only)\n", i+1, formatDuration(gap.Duration))
			}
		}
		printRecommendedChecks(w, *primary)
	}

	for _, root := range result.Roots {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s (%s)\n", root.RootSpan.Name, formatDuration(root.RootDuration))
		bar := renderTimeline(root.Timeline)
		fmt.Fprintln(w, bar)
		fmt.Fprintf(w, "covered: %s | gap: %s\n", formatDuration(root.CoveredDuration), formatDuration(root.GapDuration))
		if root.SkippedChildrenNoTime > 0 {
			fmt.Fprintf(w, "note: %d child span(s) skipped due to missing timestamps\n", root.SkippedChildrenNoTime)
		}
		if root.AggregateOnly {
			fmt.Fprintln(w, "note: positional analysis unavailable")
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Find where this missing time comes from:")
	fmt.Fprintln(w, "https://tracegap.io")

}

func PrintRepoAnalysisText(w io.Writer, result *repoanalysis.Result) {
	if result == nil || !result.Enabled {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Repo Analysis (Go)")

	if result.AsyncDetected && result.PrimaryFlow != nil {
		if strings.TrimSpace(result.AsyncWarning) != "" {
			fmt.Fprintln(w, result.AsyncWarning)
		}
		fmt.Fprintln(w, "Primary flow:")
		printFlowText(w, result.PrimaryFlow, result.Mode)
		for i := range result.AsyncFlows {
			fmt.Fprintf(w, "Async flow %d:\n", i+1)
			printFlowText(w, &result.AsyncFlows[i], result.Mode)
		}
		if len(result.CorrelationHints) > 0 {
			fmt.Fprintln(w, "Correlation hints:")
			for _, hint := range result.CorrelationHints {
				fmt.Fprintf(w, "- %s\n", hint)
			}
		}
		return
	}

	if len(result.MatchedRoots) > 1 {
		fmt.Fprintln(w, "Matched root spans:")
		for i, mr := range result.MatchedRoots {
			fmt.Fprintf(w, "%d. %s:%d\n", i+1, mr.FilePath, mr.Line)
			fmt.Fprintf(w, "   Function: %s\n", mr.Function)
			fmt.Fprintf(w, "   Confidence: %s\n", string(mr.Confidence))
		}
	} else if result.MatchedRoot != nil {
		fmt.Fprintln(w, "Matched root span:")
		fmt.Fprintf(w, "%s:%d\n", result.MatchedRoot.FilePath, result.MatchedRoot.Line)
		fmt.Fprintf(w, "Function: %s\n", result.MatchedRoot.Function)
		fmt.Fprintf(w, "Confidence: %s\n", string(result.MatchedRoot.Confidence))
	}

	if result.WeakSignal && strings.TrimSpace(result.WeakSignalMessage) != "" {
		fmt.Fprintln(w, result.WeakSignalMessage)
	}

	if result.Mode == "error-context" {
		fmt.Fprintln(w, "Most suspicious uninstrumented code paths:")
	} else {
		fmt.Fprintln(w, "Likely instrumentation opportunities:")
	}

	if len(result.Candidates) == 0 {
		fmt.Fprintln(w, "No confident candidates found.")
		return
	}

	for i, cand := range result.Candidates {
		fmt.Fprintf(w, "%d. %s:%d\n", i+1, cand.FilePath, cand.Line)
		fmt.Fprintf(w, "   Function: %s\n", cand.Function)
		fmt.Fprintf(w, "   Confidence: %s\n", string(cand.Confidence))
		fmt.Fprintln(w, "   Why:")
		for _, why := range cand.Why {
			fmt.Fprintf(w, "   - %s\n", why)
		}
		if result.Mode == "error-context" {
			fmt.Fprintln(w, "   Start here:")
		} else {
			fmt.Fprintln(w, "   Consider:")
		}
		fmt.Fprintf(w, "   %s\n", cand.ActionText)
	}
}

func printFlowText(w io.Writer, flow *repoanalysis.FlowResult, mode string) {
	if flow == nil {
		return
	}
	if strings.TrimSpace(flow.RootSpanName) != "" {
		fmt.Fprintf(w, "Root span: %s\n", flow.RootSpanName)
	}
	if flow.MatchedRoot != nil {
		fmt.Fprintln(w, "Matched root span:")
		fmt.Fprintf(w, "%s:%d\n", flow.MatchedRoot.FilePath, flow.MatchedRoot.Line)
		fmt.Fprintf(w, "Function: %s\n", flow.MatchedRoot.Function)
		fmt.Fprintf(w, "Confidence: %s\n", string(flow.MatchedRoot.Confidence))
	}
	if flow.WeakSignal && strings.TrimSpace(flow.WeakSignalMessage) != "" {
		fmt.Fprintln(w, flow.WeakSignalMessage)
	}
	if mode == "error-context" {
		fmt.Fprintln(w, "Most suspicious uninstrumented code paths:")
	} else {
		fmt.Fprintln(w, "Likely instrumentation opportunities:")
	}
	if len(flow.Candidates) == 0 {
		fmt.Fprintln(w, "No confident candidates found.")
		return
	}
	for i, cand := range flow.Candidates {
		fmt.Fprintf(w, "%d. %s:%d\n", i+1, cand.FilePath, cand.Line)
		fmt.Fprintf(w, "   Function: %s\n", cand.Function)
		fmt.Fprintf(w, "   Confidence: %s\n", string(cand.Confidence))
		fmt.Fprintln(w, "   Why:")
		for _, why := range cand.Why {
			fmt.Fprintf(w, "   - %s\n", why)
		}
		if mode == "error-context" {
			fmt.Fprintln(w, "   Start here:")
		} else {
			fmt.Fprintln(w, "   Consider:")
		}
		fmt.Fprintf(w, "   %s\n", cand.ActionText)
	}
}

func severityMessage(missingPct int) string {
	switch {
	case missingPct > 50:
		return fmt.Sprintf("🚨 Your tracing misses over half of this request's execution time (%d%% missing)", missingPct)
	case missingPct > 25:
		return fmt.Sprintf("⚠️ A significant portion of this request is not traced (%d%% missing)", missingPct)
	case missingPct > 10:
		return fmt.Sprintf("ℹ️ Some parts of this request are not traced (%d%% missing)", missingPct)
	default:
		return fmt.Sprintf("✅ Most of this request is traced (only %d%% missing)", missingPct)
	}
}

func PrintAuditJSON(w io.Writer, result analyzer.AuditResult, sourceFile string) error {
	payload := map[string]any{
		"file":           sourceFile,
		"rootsAnalyzed":  len(result.Roots),
		"detectedSchema": result.DetectedSchema,
	}

	if result.PrimaryRoot != nil {
		payload["summary"] = map[string]any{
			"traceCoveragePercent": percent(result.PrimaryRoot.CoverageRatio),
			"unaccountedTime": map[string]any{
				"percent":  100 - percent(result.PrimaryRoot.CoverageRatio),
				"duration": formatDuration(result.PrimaryRoot.GapDuration),
			},
		}
	}

	roots := make([]map[string]any, 0, len(result.Roots))
	for _, root := range result.Roots {
		item := map[string]any{
			"rootSpanId":            root.RootSpan.ID,
			"rootSpanName":          root.RootSpan.Name,
			"rootDuration":          formatDuration(root.RootDuration),
			"coveragePercent":       percent(root.CoverageRatio),
			"coveredDuration":       formatDuration(root.CoveredDuration),
			"gapDuration":           formatDuration(root.GapDuration),
			"positionalAvailable":   root.PositionalAvailable,
			"aggregateOnly":         root.AggregateOnly,
			"aggregateOnlyNote":     root.AggregateOnlyNote,
			"skippedChildrenNoTime": root.SkippedChildrenNoTime,
			"timeline": map[string]any{
				"width": root.Timeline.Width,
				"bar":   renderTimeline(root.Timeline),
			},
			"largestGaps":       gapsToJSON(root.LargestGaps, root.PositionalAvailable),
			"likelyCauses":      root.LikelyCauses,
			"recommendedChecks": root.RecommendedChecks,
		}
		roots = append(roots, item)
	}
	payload["roots"] = roots

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func gapsToJSON(gaps []analyzer.Gap, positional bool) []map[string]any {
	out := make([]map[string]any, 0, len(gaps))
	for _, g := range gaps {
		entry := map[string]any{
			"duration": formatDuration(g.Duration),
			"kind":     g.Kind,
		}
		if positional {
			entry["start"] = formatDuration(g.StartOffset)
			entry["end"] = formatDuration(g.EndOffset)
		}
		out = append(out, entry)
	}
	return out
}

func printRecommendedChecks(w io.Writer, root analyzer.RootResult) {
	fmt.Fprintln(w, "Recommended checks:")
	for _, rc := range root.RecommendedChecks {
		fmt.Fprintf(w, "- %s\n", rc)
	}
}

func describeGapContext(gap analyzer.Gap, root analyzer.RootResult) string {
	if !root.PositionalAvailable || len(root.MergedIntervals) == 0 {
		return ""
	}

	var prev *analyzer.Interval
	var next *analyzer.Interval
	for i := range root.MergedIntervals {
		in := &root.MergedIntervals[i]
		if in.EndOffset <= gap.StartOffset {
			prev = in
		}
		if next == nil && in.StartOffset >= gap.EndOffset {
			next = in
		}
	}

	prevName := ""
	nextName := ""
	if prev != nil {
		prevName = strings.TrimSpace(prev.SpanName)
	}
	if next != nil {
		nextName = strings.TrimSpace(next.SpanName)
	}

	switch {
	case gap.Kind == "after_last" && prevName != "":
		return " after " + prevName
	case gap.Kind == "before_first" && nextName != "":
		return " before " + nextName
	case prevName != "" && nextName != "":
		return " between " + prevName + " and " + nextName
	case prevName != "":
		return " after " + prevName
	case nextName != "":
		return " before " + nextName
	default:
		return ""
	}
}

func formatSchema(schema string) string {
	if strings.TrimSpace(schema) == "" {
		return ""
	}
	return strings.ToUpper(schema)
}

func renderTimeline(t analyzer.TimelineData) string {
	width := t.Width
	if width <= 0 {
		width = analyzer.DefaultTimelineWidth
	}
	coveredRune, gapRune := symbols()

	bar := make([]rune, width)
	for i := 0; i < width; i++ {
		if i < len(t.Mask) && t.Mask[i] {
			bar[i] = coveredRune
		} else {
			bar[i] = gapRune
		}
	}

	if len(t.Labels) == 0 {
		return string(bar)
	}

	sorted := make([]analyzer.LabelPlacement, len(t.Labels))
	copy(sorted, t.Labels)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].StartCol < sorted[j].StartCol })
	for _, lp := range sorted {
		if lp.StartCol < 0 || lp.StartCol >= len(bar) {
			continue
		}
		for idx, r := range []rune(lp.Text) {
			pos := lp.StartCol + idx
			if pos >= 0 && pos < len(bar) {
				bar[pos] = r
			}
		}
	}
	return string(bar)
}

func symbols() (rune, rune) {
	if supportsUnicode() {
		return '█', '·'
	}
	return '=', '.'
}

func supportsUnicode() bool {
	if os.Getenv("TGAP_ASCII") == "1" {
		return false
	}
	if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" {
		return false
	}
	lang := strings.ToUpper(strings.TrimSpace(os.Getenv("LC_ALL") + os.Getenv("LANG")))
	if strings.Contains(lang, "UTF-8") || strings.Contains(lang, "UTF8") {
		return true
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		return true
	}
	return false
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}
	if d >= time.Second {
		seconds := float64(d) / float64(time.Second)
		if seconds == math.Trunc(seconds) {
			return fmt.Sprintf("%.0fs", seconds)
		}
		return fmt.Sprintf("%.2fs", seconds)
	}
	ms := d.Milliseconds()
	if ms > 0 {
		return fmt.Sprintf("%dms", ms)
	}
	us := d.Microseconds()
	if us > 0 {
		return fmt.Sprintf("%dµs", us)
	}
	return fmt.Sprintf("%dns", d.Nanoseconds())
}

func percent(ratio float64) int {
	v := int(math.Round(ratio * 100))
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
