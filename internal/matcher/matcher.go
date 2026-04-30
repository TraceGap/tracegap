package matcher

import (
	"sort"
	"strings"

	"tracegap/internal/codegraph"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type EntryMatch struct {
	FunctionID codegraph.FunctionID
	Score      float64
	Confidence Confidence
	Reasons    []string
}

const (
	weightNameOverlap      = 2.0
	weightFileOverlap      = 1.5
	weightHandlerPattern   = 1.2
	weightPackageOverlap   = 1.0
	thresholdHighConfidence = 4.2
	thresholdMediumConfidence = 2.8
)

func MatchRootSpan(rootSpanName string, graph *codegraph.Graph) EntryMatch {
	best := EntryMatch{Confidence: ConfidenceLow}
	rootTokens := tokenize(rootSpanName)

	for id, fn := range graph.Functions {
		score := 0.0
		reasons := make([]string, 0, 4)

		nameOverlap := overlapScore(rootTokens, tokenize(fn.FuncName))
		if nameOverlap > 0 {
			score += weightNameOverlap * nameOverlap
			reasons = append(reasons, "function name overlaps root span")
		}

		fileBase := fileBaseToken(fn.FilePath)
		fileOverlap := overlapScore(rootTokens, tokenize(fileBase))
		if fileOverlap > 0 {
			score += weightFileOverlap * fileOverlap
			reasons = append(reasons, "file name aligns with root span")
		}

		if hasHandlerPattern(fn.FuncName) {
			score += weightHandlerPattern
			reasons = append(reasons, "handler-like entrypoint naming")
		}

		pkgOverlap := overlapScore(rootTokens, tokenize(fn.Package))
		if pkgOverlap > 0 {
			score += weightPackageOverlap * pkgOverlap
			reasons = append(reasons, "package semantics align with root span")
		}

		cand := EntryMatch{FunctionID: id, Score: score, Reasons: reasons, Confidence: confidenceForScore(score)}
		if cand.Score > best.Score {
			best = cand
		}
	}

	return best
}

func confidenceForScore(score float64) Confidence {
	switch {
	case score >= thresholdHighConfidence:
		return ConfidenceHigh
	case score >= thresholdMediumConfidence:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func tokenize(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	replacer := strings.NewReplacer(".", " ", "_", " ", "-", " ", "/", " ")
	s = replacer.Replace(s)
	parts := strings.Fields(strings.ToLower(s))
	if len(parts) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		uniq[p] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for p := range uniq {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func overlapScore(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	common := 0.0
	for _, x := range b {
		if _, ok := set[x]; ok {
			common++
		}
	}
	if common == 0 {
		return 0
	}
	den := float64(len(a))
	if len(b) < len(a) {
		den = float64(len(b))
	}
	if den <= 0 {
		return 0
	}
	return common / den
}

func hasHandlerPattern(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(n, "handler") || strings.Contains(n, "handle") || strings.Contains(n, "controller") || strings.Contains(n, "servehttp")
}

func fileBaseToken(path string) string {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return ""
	}
	parts := strings.Split(clean, "/")
	base := parts[len(parts)-1]
	base = strings.TrimSuffix(base, ".go")
	return base
}
