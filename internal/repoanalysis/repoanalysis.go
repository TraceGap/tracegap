package repoanalysis

import (
	"fmt"
	"sort"
	"strings"

	"tracegap/internal/analyzer"
	"tracegap/internal/codegraph"
	"tracegap/internal/codegraph/goast"
	"tracegap/internal/matcher"
	"tracegap/internal/parser"
	"tracegap/internal/repoanalysis/detect"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

const (
	weightNoSpan              = 3.5
	weightExternalOperation   = 3.0
	weightReachablePath       = 2.0
	weightGapAlignment        = 2.2
	weightErrorContextAlign   = 1.8
	weightSemanticRootAlign   = 1.2
	weightErrorHandling       = 0.8
	penaltyWeakEvidence       = 1.5
	penaltyNoEntrypointPath   = 1.0

	thresholdHighConfidence         = 8.5
	thresholdMediumConfidence       = 5.5
	thresholdCandidateInclusion     = 3.0
	thresholdStrongEvidenceFallback = 5.0

	defaultCandidateCount = 3
	maxCandidateCount     = 5
	maxDepth              = 6
)

type MatchedRoot struct {
	FilePath    string
	Line        int
	Function    string
	Confidence  Confidence
	Why         []string
}

type Candidate struct {
	FilePath    string
	Line        int
	Function    string
	Confidence  Confidence
	Why         []string
	StartHere   string
	Score       float64
}

type Result struct {
	Enabled           bool
	RepoType          detect.RepoType
	Mode              string
	WeakSignal        bool
	WeakSignalMessage string
	MatchedRoot       *MatchedRoot
	Candidates        []Candidate
}

func Analyze(repoPath string, audit analyzer.AuditResult, spans []parser.Span) (*Result, error) {
	limits := detect.DefaultLimits()
	detection, err := detect.DetectRepoType(repoPath, limits)
	if err != nil {
		return nil, fmt.Errorf("repo detection failed: %w", err)
	}

	result := &Result{Enabled: true, RepoType: detection.Type, Mode: analysisMode(spans)}
	if detection.Type != detect.RepoTypeGo {
		result.WeakSignal = true
		result.WeakSignalMessage = "Weak signal: repo type is not yet supported for repo-aware analysis."
		return result, nil
	}

	graph, err := goast.BuildGraph(repoPath, goast.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("go graph extraction failed: %w", err)
	}
	if len(graph.Functions) == 0 {
		result.WeakSignal = true
		result.WeakSignalMessage = "Weak signal: no repository functions were extracted for analysis."
		return result, nil
	}

	rootName := ""
	if audit.PrimaryRoot != nil {
		rootName = audit.PrimaryRoot.RootSpan.Name
	}
	entry := matcher.MatchRootSpan(rootName, graph)
	entryNode := graph.Functions[entry.FunctionID]
	entryConfidence := mapMatcherConfidence(entry.Confidence)

	if entryNode != nil {
		result.MatchedRoot = &MatchedRoot{
			FilePath:   entryNode.FilePath,
			Line:       entryNode.StartLine,
			Function:   entryNode.QualifiedName,
			Confidence: entryConfidence,
			Why:        append([]string(nil), entry.Reasons...),
		}
	}

	reachable := map[codegraph.FunctionID]struct{}{}
	if entryConfidence == ConfidenceHigh || entryConfidence == ConfidenceMedium {
		reachable = walkReachable(graph, entry.FunctionID, maxDepth)
	} else {
		result.WeakSignal = true
		result.WeakSignalMessage = "Weak signal: no confident root entrypoint match found, so reachable-path claims are intentionally omitted."
	}

	rootTokens := tokenize(rootName)
	gapTokens := gapContextTokens(audit.PrimaryRoot)
	errorTokens := errorTokens(spans)

	candidates := make([]Candidate, 0, 16)
	for _, id := range graph.SortedIDs() {
		fn := graph.Functions[id]
		cand, ok := scoreCandidate(fn, id, reachable, result.WeakSignal, rootTokens, gapTokens, errorTokens)
		if !ok {
			continue
		}
		candidates = append(candidates, cand)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			if candidates[i].FilePath == candidates[j].FilePath {
				return candidates[i].Line < candidates[j].Line
			}
			return candidates[i].FilePath < candidates[j].FilePath
		}
		return candidates[i].Score > candidates[j].Score
	})

	limit := defaultCandidateCount
	if len(candidates) > defaultCandidateCount {
		for i := defaultCandidateCount; i < len(candidates) && i < maxCandidateCount; i++ {
			if candidates[i].Score >= thresholdStrongEvidenceFallback {
				limit = i + 1
			}
		}
	}
	if limit > len(candidates) {
		limit = len(candidates)
	}
	result.Candidates = candidates[:limit]

	return result, nil
}

func mapMatcherConfidence(c matcher.Confidence) Confidence {
	switch c {
	case matcher.ConfidenceHigh:
		return ConfidenceHigh
	case matcher.ConfidenceMedium:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func scoreCandidate(
	fn *codegraph.FunctionNode,
	id codegraph.FunctionID,
	reachable map[codegraph.FunctionID]struct{},
	weakSignal bool,
	rootTokens, gapTokens, errorTokens []string,
) (Candidate, bool) {
	if fn.StartsSpan {
		return Candidate{}, false
	}

	score := 0.0
	why := make([]string, 0, 6)
	score += weightNoSpan
	why = append(why, "No span detected in function body")

	extStrength := float64(fn.ExternalOps.Count)
	if extStrength > 0 {
		if extStrength > 2 {
			extStrength = 2
		}
		score += weightExternalOperation * extStrength
		why = append(why, "Performs likely external operation: "+strings.Join(fn.ExternalOps.Reasons, ", "))
	}

	if _, ok := reachable[id]; ok {
		score += weightReachablePath
		why = append(why, "On a reachable path from matched entrypoint")
	}

	gapAlign := overlapScore(tokenize(fn.FuncName+" "+fn.FilePath+" "+fn.Package), gapTokens)
	if gapAlign > 0 {
		score += weightGapAlignment * gapAlign
		why = append(why, "Semantics align with largest trace gaps")
	}

	errorAlign := overlapScore(tokenize(fn.FuncName+" "+fn.FilePath+" "+fn.Package), errorTokens)
	if errorAlign > 0 {
		score += weightErrorContextAlign * errorAlign
		why = append(why, "Semantics align with error context")
	}

	rootAlign := overlapScore(tokenize(fn.FuncName+" "+fn.FilePath+" "+fn.Package), rootTokens)
	if rootAlign > 0 {
		score += weightSemanticRootAlign * rootAlign
		why = append(why, "Semantics align with root span")
	}

	if fn.HandlesError {
		score += weightErrorHandling
		why = append(why, "Contains error handling behavior")
	}

	if weakSignal {
		score -= penaltyNoEntrypointPath
		if extStrength == 0 && gapAlign == 0 && errorAlign == 0 {
			score -= penaltyWeakEvidence
		}
	}

	if score < thresholdCandidateInclusion {
		return Candidate{}, false
	}
	if weakSignal && score < thresholdStrongEvidenceFallback {
		return Candidate{}, false
	}

	cand := Candidate{
		FilePath:   fn.FilePath,
		Line:       fn.StartLine,
		Function:   fn.QualifiedName,
		Confidence: confidenceFromScore(score),
		Why:        why,
		StartHere:  "Add or verify instrumentation around " + fn.FuncName + "()",
		Score:      score,
	}
	if weakSignal {
		cand.Confidence = ConfidenceLow
	}
	return cand, true
}

func walkReachable(graph *codegraph.Graph, start codegraph.FunctionID, depthLimit int) map[codegraph.FunctionID]struct{} {
	reachable := make(map[codegraph.FunctionID]struct{})
	if _, ok := graph.Functions[start]; !ok {
		return reachable
	}
	type item struct {
		id    codegraph.FunctionID
		depth int
	}
	queue := []item{{id: start, depth: 0}}
	reachable[start] = struct{}{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= depthLimit {
			continue
		}
		node := graph.Functions[cur.id]
		for _, next := range node.LocalCalls {
			if _, seen := reachable[next]; seen {
				continue
			}
			reachable[next] = struct{}{}
			queue = append(queue, item{id: next, depth: cur.depth + 1})
		}
	}
	return reachable
}

func analysisMode(spans []parser.Span) string {
	for _, sp := range spans {
		name := strings.ToLower(sp.Name)
		if strings.Contains(name, "error") || strings.Contains(name, "exception") || strings.Contains(name, "fail") {
			return "error-context"
		}
	}
	return "instrumentation-opportunity"
}

func tokenize(s string) []string {
	repl := strings.NewReplacer(".", " ", "_", " ", "-", " ", "/", " ")
	s = repl.Replace(strings.ToLower(strings.TrimSpace(s)))
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		uniq[p] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for p := range uniq {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func overlapScore(tokens, target []string) float64 {
	if len(tokens) == 0 || len(target) == 0 {
		return 0
	}
	set := make(map[string]struct{}, len(target))
	for _, t := range target {
		set[t] = struct{}{}
	}
	common := 0.0
	for _, t := range tokens {
		if _, ok := set[t]; ok {
			common++
		}
	}
	if common == 0 {
		return 0
	}
	den := float64(len(target))
	if len(tokens) < len(target) {
		den = float64(len(tokens))
	}
	if den <= 0 {
		return 0
	}
	return common / den
}

func confidenceFromScore(score float64) Confidence {
	switch {
	case score >= thresholdHighConfidence:
		return ConfidenceHigh
	case score >= thresholdMediumConfidence:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func errorTokens(spans []parser.Span) []string {
	all := make([]string, 0, 8)
	for _, sp := range spans {
		name := strings.ToLower(sp.Name)
		if strings.Contains(name, "error") || strings.Contains(name, "exception") || strings.Contains(name, "fail") {
			all = append(all, tokenize(sp.Name)...)
		}
	}
	return dedupeTokens(all)
}

func gapContextTokens(root *analyzer.RootResult) []string {
	if root == nil || len(root.LargestGaps) == 0 || len(root.MergedIntervals) == 0 {
		return nil
	}
	all := make([]string, 0, 8)
	for _, gap := range root.LargestGaps {
		prev, next := neighborSpanNames(gap, root.MergedIntervals)
		if prev != "" {
			all = append(all, tokenize(prev)...)
		}
		if next != "" {
			all = append(all, tokenize(next)...)
		}
	}
	return dedupeTokens(all)
}

func neighborSpanNames(gap analyzer.Gap, intervals []analyzer.Interval) (string, string) {
	var prev, next string
	for i := range intervals {
		in := intervals[i]
		if in.EndOffset <= gap.StartOffset {
			prev = in.SpanName
		}
		if next == "" && in.StartOffset >= gap.EndOffset {
			next = in.SpanName
		}
	}
	return prev, next
}

func dedupeTokens(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		if strings.TrimSpace(t) == "" {
			continue
		}
		set[t] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
