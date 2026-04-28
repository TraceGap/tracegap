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
	fmt.Fprintln(w)
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
			if primary.PositionalAvailable {
				fmt.Fprintf(w, "%d. %s-%s (%s)\n", i+1, formatDuration(gap.StartOffset), formatDuration(gap.EndOffset), formatDuration(gap.Duration))
			} else {
				fmt.Fprintf(w, "%d. %s (aggregate-only)\n", i+1, formatDuration(gap.Duration))
			}
			printGuidance(w, *primary)
		}
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

	if gapPct >= 30 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Your tracing likely does not cover a significant portion of request time.")
	}
}

func PrintAuditJSON(w io.Writer, result analyzer.AuditResult, sourceFile string) error {
	payload := map[string]any{
		"file":          sourceFile,
		"rootsAnalyzed": len(result.Roots),
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

func printGuidance(w io.Writer, root analyzer.RootResult) {
	fmt.Fprintln(w, "   Likely causes:")
	for _, c := range root.LikelyCauses {
		fmt.Fprintf(w, "   - %s\n", c)
	}
	fmt.Fprintln(w, "   Recommended checks:")
	for i, rc := range root.RecommendedChecks {
		fmt.Fprintf(w, "   %d. %s\n", i+1, rc)
	}
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
