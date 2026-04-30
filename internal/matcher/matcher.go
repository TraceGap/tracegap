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
	weightRootNameOverlap       = 3.2
	weightRootFileOverlap       = 2.0
	weightRootPackageOverlap    = 1.8
	weightHandlerPattern        = 2.0
	weightHTTPHandlerSignature  = 2.4
	penaltyChildSemanticOverlap = 2.4
	penaltyDownstreamSemantic   = 1.8
	penaltyExternalHeavyRoot    = 1.0

	thresholdHighConfidence   = 5.2
	thresholdMediumConfidence = 3.2
	minimumEntrypointScore    = 2.4
	minimumConfidenceMargin   = 0.8
)

func MatchRootSpan(rootSpanName string, childSpanNames []string, graph *codegraph.Graph) EntryMatch {
	best := EntryMatch{Confidence: ConfidenceLow}
	secondBest := EntryMatch{Confidence: ConfidenceLow}
	rootTokens := tokenize(rootSpanName)
	childTokens := tokenize(strings.Join(childSpanNames, " "))

	for id, fn := range graph.Functions {
		score := 0.0
		reasons := make([]string, 0, 8)

		fnNameTokens := tokenize(fn.FuncName)
		fnFileTokens := tokenize(fileBaseToken(fn.FilePath))
		fnPkgTokens := tokenize(fn.Package)
		allFnTokens := tokenize(fn.FuncName + " " + fn.FilePath + " " + fn.Package)

		nameOverlap := overlapScore(rootTokens, fnNameTokens)
		if nameOverlap > 0 {
			score += weightRootNameOverlap * nameOverlap
			reasons = append(reasons, "function name overlaps root span")
		}

		fileOverlap := overlapScore(rootTokens, fnFileTokens)
		if fileOverlap > 0 {
			score += weightRootFileOverlap * fileOverlap
			reasons = append(reasons, "file name aligns with root span")
		}

		if hasHandlerPattern(fn.FuncName) {
			score += weightHandlerPattern
			reasons = append(reasons, "handler-like entrypoint naming")
		}
		if fn.IsHTTPHandler {
			score += weightHTTPHandlerSignature
			reasons = append(reasons, "HTTP handler signature")
		}

		pkgOverlap := overlapScore(rootTokens, fnPkgTokens)
		if pkgOverlap > 0 {
			score += weightRootPackageOverlap * pkgOverlap
			reasons = append(reasons, "package semantics align with root span")
		}

		childOverlap := overlapScore(childTokens, allFnTokens)
		if childOverlap > 0 {
			score -= penaltyChildSemanticOverlap * childOverlap
			reasons = append(reasons, "penalized for stronger child-span semantics")
		}

		downstream := downstreamPenalty(fn)
		if downstream > 0 {
			score -= penaltyDownstreamSemantic * downstream
			reasons = append(reasons, "penalized for downstream/client/repository semantics")
		}

		if fn.ExternalOps.Count > 0 {
			score -= penaltyExternalHeavyRoot
			reasons = append(reasons, "penalized for primarily external-operation profile")
		}

		cand := EntryMatch{FunctionID: id, Score: score, Reasons: reasons, Confidence: confidenceForScore(score)}
		if cand.Score > best.Score {
			secondBest = best
			best = cand
		} else if cand.Score > secondBest.Score {
			secondBest = cand
		}
	}

	if best.Score < minimumEntrypointScore {
		best.Confidence = ConfidenceLow
		return best
	}
	if best.Score-secondBest.Score < minimumConfidenceMargin {
		best.Confidence = ConfidenceLow
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

func downstreamPenalty(fn *codegraph.FunctionNode) float64 {
	tokens := tokenize(fn.FuncName + " " + fn.FilePath + " " + fn.Package)
	if len(tokens) == 0 {
		return 0
	}
	downstreamWords := map[string]struct{}{
		"client": {}, "repository": {}, "repo": {}, "gateway": {}, "storage": {}, "store": {}, "dao": {}, "adapter": {},
		"reserve": {}, "charge": {}, "save": {}, "execute": {}, "call": {}, "query": {}, "publish": {}, "send": {},
	}
	matches := 0.0
	for _, tok := range tokens {
		if _, ok := downstreamWords[tok]; ok {
			matches++
		}
	}
	if matches == 0 {
		return 0
	}
	den := float64(len(tokens))
	if den <= 0 {
		return 0
	}
	v := matches / den
	if v > 1 {
		return 1
	}
	return v
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
