package repoanalysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

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
	weightSemanticSignal      = 1.4
	weightErrorHandling       = 0.8
	weightGapAfterDownstream  = 1.6
	penaltyChildSpanSemantic  = 2.0
	penaltyGapPrevSpanMatch   = 3.0
	penaltyWeakEvidence       = 1.5
	penaltyNoEntrypointPath   = 1.0
	penaltyEntrypointBias     = 2.5

	thresholdHighConfidence         = 8.5
	thresholdMediumConfidence       = 5.5
	thresholdCandidateInclusion     = 3.0
	thresholdStrongEvidenceFallback = 6.5

	defaultCandidateCount = 3
	maxCandidateCount     = 5
	maxDepth              = 6

	minGapEvidenceDuration = 25 * time.Millisecond
	minGapEvidenceRatio    = 0.05
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
	ActionText  string
	Score       float64
}

type Result struct {
	Enabled           bool
	RepoType          detect.RepoType
	Mode              string
	WeakSignal        bool
	WeakSignalMessage string
	MatchedRoot       *MatchedRoot
	MatchedRoots      []MatchedRoot
	Candidates        []Candidate
	AsyncDetected     bool
	AsyncWarning      string
	CorrelationHints  []string
	PrimaryFlow       *FlowResult
	AsyncFlows        []FlowResult
}

type FlowResult struct {
	RootSpanName       string
	RootSpanID         string
	MatchedRoot        *MatchedRoot
	WeakSignal         bool
	WeakSignalMessage  string
	Candidates         []Candidate
	Classification     string
}

type rootContext struct {
	root                 *analyzer.RootResult
	rootName             string
	rootMetaTokens       []string
	entryID              codegraph.FunctionID
	entryNode            *codegraph.FunctionNode
	entryConfidence      Confidence
	entryReasons         []string
	reachable            map[codegraph.FunctionID]struct{}
	weakSignal           bool
	rootTokens           []string
	childTokens          []string
	evidenceGaps         []analyzer.Gap
	gapTokens            []string
	primaryGapPrevTokens []string
	primaryGapKind       string
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

	contexts := buildRootContexts(audit, spans, graph)
	if len(contexts) == 0 {
		result.WeakSignal = true
		result.WeakSignalMessage = "Weak signal: no root spans available for repo-aware matching."
		return result, nil
	}

	primaryIdx, secondaryIdx := splitPrimaryAndSecondary(contexts)
	asyncDetected := detectAsyncExecution(contexts, primaryIdx, secondaryIdx)
	result.AsyncDetected = asyncDetected
	if asyncDetected {
		result.AsyncWarning = "Async execution detected across multiple services"
	}

	matchedRoots := make([]MatchedRoot, 0, len(contexts))
	anyConfident := false
	for _, ctx := range contexts {
		if ctx.entryNode == nil {
			continue
		}
		matchedRoots = append(matchedRoots, MatchedRoot{
			FilePath:   ctx.entryNode.FilePath,
			Line:       ctx.entryNode.StartLine,
			Function:   ctx.entryNode.QualifiedName,
			Confidence: ctx.entryConfidence,
			Why:        append([]string(nil), ctx.entryReasons...),
		})
		if ctx.entryConfidence == ConfidenceHigh || ctx.entryConfidence == ConfidenceMedium {
			anyConfident = true
		}
	}
	if len(matchedRoots) > 0 {
		sort.Slice(matchedRoots, func(i, j int) bool {
			ci := confidenceRank(matchedRoots[i].Confidence)
			cj := confidenceRank(matchedRoots[j].Confidence)
			if ci == cj {
				if matchedRoots[i].FilePath == matchedRoots[j].FilePath {
					return matchedRoots[i].Line < matchedRoots[j].Line
				}
				return matchedRoots[i].FilePath < matchedRoots[j].FilePath
			}
			return ci > cj
		})
		result.MatchedRoots = matchedRoots
		result.MatchedRoot = &result.MatchedRoots[0]
	}

	if !anyConfident {
		result.WeakSignal = true
		result.WeakSignalMessage = "Weak signal: no confident root entrypoint match found, so reachable-path claims are intentionally omitted."
	}

	errorTokens := errorTokens(spans)
	perContextCandidates := make([][]Candidate, len(contexts))
	for i, ctx := range contexts {
		perContextCandidates[i] = scoreCandidatesForContext(graph, ctx, result.Mode, errorTokens)
	}

	candidateByKey := map[string]Candidate{}
	for _, set := range perContextCandidates {
		for _, cand := range set {
			key := candidateKey(cand)
			existing, exists := candidateByKey[key]
			if !exists || cand.Score > existing.Score {
				candidateByKey[key] = cand
			}
		}
	}
	candidates := make([]Candidate, 0, len(candidateByKey))
	for _, cand := range candidateByKey {
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

	result.Candidates = limitCandidates(candidates)

	if asyncDetected {
		primaryCtx := contexts[primaryIdx]
		primaryMatched := toMatchedRoot(primaryCtx)
		result.PrimaryFlow = &FlowResult{
			RootSpanName:      primaryCtx.rootName,
			RootSpanID:        strings.TrimSpace(primaryCtx.root.RootSpan.ID),
			MatchedRoot:       primaryMatched,
			WeakSignal:        primaryCtx.weakSignal,
			WeakSignalMessage: weakSignalMessageFor(primaryCtx.weakSignal),
			Candidates:        limitCandidates(perContextCandidates[primaryIdx]),
			Classification:    "primary",
		}
		result.MatchedRoot = primaryMatched
		result.Candidates = append([]Candidate(nil), result.PrimaryFlow.Candidates...)

		asyncFlows := make([]FlowResult, 0, len(secondaryIdx))
		for _, idx := range secondaryIdx {
			ctx := contexts[idx]
			asyncFlows = append(asyncFlows, FlowResult{
				RootSpanName:      ctx.rootName,
				RootSpanID:        strings.TrimSpace(ctx.root.RootSpan.ID),
				MatchedRoot:       toMatchedRoot(ctx),
				WeakSignal:        ctx.weakSignal,
				WeakSignalMessage: weakSignalMessageFor(ctx.weakSignal),
				Candidates:        limitCandidates(perContextCandidates[idx]),
				Classification:    "async",
			})
		}
		result.AsyncFlows = asyncFlows
		result.CorrelationHints = correlationHints(primaryCtx, contexts, secondaryIdx)
	}

	return result, nil
}

func scoreCandidatesForContext(graph *codegraph.Graph, ctx rootContext, mode string, errorTokens []string) []Candidate {
	candidates := make([]Candidate, 0, 16)
	for _, id := range graph.SortedIDs() {
		fn := graph.Functions[id]
		cand, ok := scoreCandidate(fn, id, ctx.entryID, ctx.rootName, mode, ctx.root, ctx.evidenceGaps, ctx.primaryGapPrevTokens, ctx.primaryGapKind, ctx.reachable, ctx.weakSignal, ctx.rootTokens, ctx.childTokens, ctx.gapTokens, errorTokens)
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
	return candidates
}

func limitCandidates(candidates []Candidate) []Candidate {
	if len(candidates) == 0 {
		return nil
	}
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
	return append([]Candidate(nil), candidates[:limit]...)
}

func toMatchedRoot(ctx rootContext) *MatchedRoot {
	if ctx.entryNode == nil {
		return nil
	}
	return &MatchedRoot{
		FilePath:   ctx.entryNode.FilePath,
		Line:       ctx.entryNode.StartLine,
		Function:   ctx.entryNode.QualifiedName,
		Confidence: ctx.entryConfidence,
		Why:        append([]string(nil), ctx.entryReasons...),
	}
}

func weakSignalMessageFor(weak bool) string {
	if !weak {
		return ""
	}
	return "Weak signal: no confident root entrypoint match found, so reachable-path claims are intentionally omitted."
}

func splitPrimaryAndSecondary(contexts []rootContext) (int, []int) {
	if len(contexts) == 0 {
		return -1, nil
	}
	best := 0
	bestScore := rootPriorityScore(contexts[0])
	for i := 1; i < len(contexts); i++ {
		s := rootPriorityScore(contexts[i])
		if s > bestScore {
			best = i
			bestScore = s
			continue
		}
		if s == bestScore && contexts[i].root != nil && contexts[best].root != nil {
			if contexts[i].root.RootDuration > contexts[best].root.RootDuration {
				best = i
			}
		}
	}
	secondary := make([]int, 0, len(contexts)-1)
	for i := range contexts {
		if i == best {
			continue
		}
		secondary = append(secondary, i)
	}
	return best, secondary
}

func rootPriorityScore(ctx rootContext) float64 {
	if ctx.root == nil {
		return -1
	}
	name := strings.ToLower(strings.TrimSpace(ctx.rootName))
	tokens := make(map[string]struct{}, len(ctx.rootTokens))
	for _, t := range ctx.rootTokens {
		tokens[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	score := 0.0
	for _, key := range []string{"web", "server", "http", "route", "request", "api", "handler", "frontend"} {
		if _, ok := tokens[key]; ok {
			score += 1.2
		}
	}
	for _, key := range []string{"worker", "consumer", "queue", "stream", "messaging", "message", "kafka", "pubsub", "event", "job"} {
		if _, ok := tokens[key]; ok {
			score -= 1.3
		}
	}
	if strings.Contains(name, "request") || strings.Contains(name, "http") || strings.Contains(name, "api") {
		score += 1.5
	}
	if strings.Contains(name, "consume") || strings.Contains(name, "worker") || strings.Contains(name, "queue") || strings.Contains(name, "stream") {
		score -= 1.5
	}
	if ctx.entryConfidence == ConfidenceHigh {
		score += 0.8
	} else if ctx.entryConfidence == ConfidenceMedium {
		score += 0.3
	}
	return score
}

func detectAsyncExecution(contexts []rootContext, primaryIdx int, secondaryIdx []int) bool {
	if len(contexts) <= 1 || primaryIdx < 0 {
		return false
	}
	if len(secondaryIdx) == 0 {
		return false
	}
	overlap := false
	for _, idx := range secondaryIdx {
		if rootsOverlap(contexts[primaryIdx].root, contexts[idx].root) {
			overlap = true
			break
		}
	}
	if !overlap {
		return false
	}
	if hasServiceDiversity(contexts, primaryIdx, secondaryIdx) {
		return true
	}
	for _, idx := range secondaryIdx {
		if looksAsyncRoot(contexts[idx]) {
			return true
		}
	}
	return false
}

func rootsOverlap(a, b *analyzer.RootResult) bool {
	if a == nil || b == nil {
		return false
	}
	as := a.RootSpan
	bs := b.RootSpan
	if !as.HasTimestamps() || !bs.HasTimestamps() {
		return false
	}
	return as.Start.Before(bs.End) && bs.Start.Before(as.End)
}

func hasServiceDiversity(contexts []rootContext, primaryIdx int, secondaryIdx []int) bool {
	seen := map[string]struct{}{}
	if s := inferredService(contexts[primaryIdx]); s != "" {
		seen[s] = struct{}{}
	}
	for _, idx := range secondaryIdx {
		if s := inferredService(contexts[idx]); s != "" {
			seen[s] = struct{}{}
		}
	}
	return len(seen) >= 2
}

func inferredService(ctx rootContext) string {
	name := strings.ToLower(strings.TrimSpace(ctx.rootName))
	if i := strings.Index(name, "."); i > 0 {
		return name[:i]
	}
	for _, t := range ctx.rootMetaTokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if t == "http" || t == "request" || t == "route" || t == "server" || t == "web" {
			continue
		}
		return t
	}
	return ""
}

func looksAsyncRoot(ctx rootContext) bool {
	tokens := make(map[string]struct{}, len(ctx.rootTokens))
	for _, t := range ctx.rootTokens {
		tokens[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	for _, key := range []string{"worker", "consumer", "queue", "stream", "messaging", "kafka", "pubsub", "event", "job"} {
		if _, ok := tokens[key]; ok {
			return true
		}
	}
	name := strings.ToLower(strings.TrimSpace(ctx.rootName))
	return strings.Contains(name, "consume") || strings.Contains(name, "worker") || strings.Contains(name, "queue") || strings.Contains(name, "stream")
}

func correlationHints(primary rootContext, contexts []rootContext, secondaryIdx []int) []string {
	if len(secondaryIdx) == 0 {
		return nil
	}
	primarySet := make(map[string]struct{}, len(primary.rootMetaTokens))
	for _, t := range primary.rootMetaTokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if isCorrelationToken(t) {
			primarySet[t] = struct{}{}
		}
	}
	hints := make([]string, 0, len(secondaryIdx))
	for _, idx := range secondaryIdx {
		shared := make([]string, 0, 4)
		seen := map[string]struct{}{}
		for _, t := range contexts[idx].rootMetaTokens {
			t = strings.ToLower(strings.TrimSpace(t))
			if !isCorrelationToken(t) {
				continue
			}
			if _, ok := primarySet[t]; !ok {
				continue
			}
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			shared = append(shared, t)
		}
		if len(shared) == 0 {
			continue
		}
		sort.Strings(shared)
		if len(shared) > 3 {
			shared = shared[:3]
		}
		hints = append(hints, "Shared identifiers between \""+primary.rootName+"\" and \""+contexts[idx].rootName+"\": "+strings.Join(shared, ", "))
	}
	if len(hints) == 0 {
		hints = append(hints, "No shared user/event/request identifiers found in span metadata.")
	}
	return hints
}

func isCorrelationToken(t string) bool {
	if t == "" {
		return false
	}
	if strings.Contains(t, "user") || strings.Contains(t, "event") || strings.Contains(t, "request") || strings.Contains(t, "trace") {
		return true
	}
	if len(t) >= 8 {
		hasDigit := false
		for _, r := range t {
			if r >= '0' && r <= '9' {
				hasDigit = true
				break
			}
		}
		if hasDigit {
			return true
		}
	}
	return false
}

func buildRootContexts(audit analyzer.AuditResult, spans []parser.Span, graph *codegraph.Graph) []rootContext {
	roots := make([]*analyzer.RootResult, 0, len(audit.Roots))
	for i := range audit.Roots {
		roots = append(roots, &audit.Roots[i])
	}
	if len(roots) == 0 && audit.PrimaryRoot != nil {
		roots = append(roots, audit.PrimaryRoot)
	}
	if len(roots) == 0 {
		return nil
	}
	contexts := make([]rootContext, 0, len(roots))
	for _, root := range roots {
		if root == nil {
			continue
		}
		rootName := strings.TrimSpace(root.RootSpan.Name)
		rootMetaTokens := rootMetadataTokens(spans, root)
		childNames := directChildSpanNames(spans, root)
		entry := matcher.MatchRootSpan(rootName, rootMetaTokens, childNames, graph)
		entryConfidence := mapMatcherConfidence(entry.Confidence)
		reachable := map[codegraph.FunctionID]struct{}{}
		weak := true
		if entryConfidence == ConfidenceHigh || entryConfidence == ConfidenceMedium {
			reachable = walkReachable(graph, entry.FunctionID, maxDepth)
			weak = false
		}
		evidenceGaps := selectEvidenceGaps(root)
		contexts = append(contexts, rootContext{
			root:                 root,
			rootName:             rootName,
			rootMetaTokens:       rootMetaTokens,
			entryID:              entry.FunctionID,
			entryNode:            graph.Functions[entry.FunctionID],
			entryConfidence:      entryConfidence,
			entryReasons:         append([]string(nil), entry.Reasons...),
			reachable:            reachable,
			weakSignal:           weak,
			rootTokens:           dedupeTokens(append(tokenize(rootName), rootMetaTokens...)),
			childTokens:          tokenize(strings.Join(childNames, " ")),
			evidenceGaps:         evidenceGaps,
			gapTokens:            gapContextTokens(root, evidenceGaps),
			primaryGapPrevTokens: primaryGapPrevSpanTokens(root, evidenceGaps),
			primaryGapKind:       primaryGapKind(evidenceGaps),
		})
	}
	return contexts
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func candidateKey(c Candidate) string {
	return c.FilePath + "|" + fmt.Sprintf("%d", c.Line) + "|" + c.Function
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
	entryID codegraph.FunctionID,
	rootName string,
	mode string,
	root *analyzer.RootResult,
	evidenceGaps []analyzer.Gap,
	primaryGapPrevTokens []string,
	primaryGapKind string,
	reachable map[codegraph.FunctionID]struct{},
	weakSignal bool,
	rootTokens, childTokens, gapTokens, errorTokens []string,
) (Candidate, bool) {
	if fn.StartsSpan {
		return Candidate{}, false
	}

	score := 0.0
	why := make([]string, 0, 6)
	score += weightNoSpan
	why = append(why, "No span detected in this function")

	extStrength := float64(fn.ExternalOps.Count)
	if extStrength > 0 {
		if extStrength > 2 {
			extStrength = 2
		}
		score += weightExternalOperation * extStrength
		why = append(why, externalReasonLine(fn.ExternalOps.Reasons))
	}

	onReachablePath := false
	if _, ok := reachable[id]; ok {
		onReachablePath = true
		score += weightReachablePath
		if strings.TrimSpace(rootName) != "" {
			why = append(why, "On a reachable path from "+rootName)
		} else {
			why = append(why, "On a reachable path from matched entrypoint")
		}
	}

	semanticTokens := tokenize(fn.FuncName + " " + fn.FilePath + " " + fn.Package)
	semanticSignal := downstreamSemanticSignal(fn, semanticTokens)
	if semanticSignal > 0 {
		score += weightSemanticSignal * semanticSignal
		why = append(why, "Contains downstream/retry/client semantics")
	}
	gapAlign := overlapScore(semanticTokens, gapTokens)
	if gapAlign > 0 {
		score += weightGapAlignment * gapAlign
	}
	if line, ok := gapWhyLine(root, evidenceGaps, fn, mode, onReachablePath, extStrength > 0, gapAlign); ok {
		why = append(why, line)
	} else if gapAlign > 0 {
		why = append(why, "Semantics align with largest trace gaps")
	}

	errorAlign := overlapScore(semanticTokens, errorTokens)
	if errorAlign > 0 {
		score += weightErrorContextAlign * errorAlign
		why = append(why, "Semantics align with error context")
	}

	rootAlign := overlapScore(semanticTokens, rootTokens)
	if rootAlign > 0 {
		score += weightSemanticRootAlign * rootAlign
		why = append(why, "Semantics align with root span")
	}

	childAlign := overlapScore(semanticTokens, childTokens)
	if childAlign > 0 {
		score -= penaltyChildSpanSemantic * childAlign
	}
	prevGapChildAlign := overlapScore(semanticTokens, primaryGapPrevTokens)
	if prevGapChildAlign >= 0.5 {
		score -= penaltyGapPrevSpanMatch * prevGapChildAlign
	}
	if primaryGapKind == "after_last" && onReachablePath && extStrength > 0 && prevGapChildAlign < 0.3 {
		score += weightGapAfterDownstream
	}

	if fn.HandlesError {
		score += weightErrorHandling
		if mode == "error-context" {
			why = append(why, "Contains error handling behavior")
		}
	}

	if extStrength == 0 && isInternalHelperLike(fn) {
		if gapAlign < 0.65 || errorAlign < 0.35 {
			// Helper-like internal functions need strong gap alignment and error relevance.
			return Candidate{}, false
		}
	}

	hasRequiredEvidence := extStrength > 0 || gapAlign >= 0.65 || errorAlign >= 0.45 || semanticSignal >= 0.60
	if !hasRequiredEvidence {
		// Exclude candidates that are only "reachable + no span" noise.
		return Candidate{}, false
	}

	isEntrypoint := id == entryID
	if isEntrypoint {
		// The matched root should usually be context, not a candidate.
		veryStrongBoundaryEvidence := extStrength >= 1 && (gapAlign >= 0.85 || errorAlign >= 0.75 || semanticSignal >= 0.90) && (fn.HandlesError || semanticSignal >= 0.95)
		if !veryStrongBoundaryEvidence {
			return Candidate{}, false
		}
		score -= penaltyEntrypointBias
	}

	if childAlign >= 0.65 && extStrength == 0 && gapAlign < 0.45 && errorAlign == 0 {
		// Avoid preferring functions that semantically map to already-instrumented child spans.
		return Candidate{}, false
	}
	if prevGapChildAlign >= 0.7 && childAlign >= 0.5 && gapAlign < 0.6 && errorAlign == 0 {
		// For gaps after known child spans, suppress candidates that map back to that already-instrumented child path.
		return Candidate{}, false
	}
	if primaryGapKind == "after_last" && prevGapChildAlign >= 0.55 {
		independentFromPrev := errorAlign >= 0.65 || (semanticSignal >= 0.80 && extStrength > 0 && (gapAlign-prevGapChildAlign) >= 0.20)
		if !independentFromPrev {
			// Gap-after-X should not point back to X unless there is very strong independent evidence.
			return Candidate{}, false
		}
		score -= penaltyGapPrevSpanMatch * prevGapChildAlign
	}
	if primaryGapKind == "after_last" && prevGapChildAlign >= 0.5 && extStrength > 0 && gapAlign < 0.7 && errorAlign == 0 {
		// Do not top-rank operations that strongly map to the already-instrumented preceding span.
		return Candidate{}, false
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
		ActionText: actionTextForMode(mode, fn),
		Score:      score,
	}
	if weakSignal {
		cand.Confidence = ConfidenceLow
	}
	return cand, true
}

func actionTextForMode(mode string, fn *codegraph.FunctionNode) string {
	name := functionLabel(fn)
	if mode == "instrumentation-opportunity" {
		return "Add a span around " + name + " to improve trace coverage."
	}
	return "Add or verify instrumentation around " + name
}

func functionLabel(fn *codegraph.FunctionNode) string {
	if strings.TrimSpace(fn.Package) == "" {
		return fn.FuncName + "()"
	}
	if strings.TrimSpace(fn.Receiver) != "" {
		return fn.Package + ".(*" + fn.Receiver + ")." + fn.FuncName + "()"
	}
	return fn.Package + "." + fn.FuncName + "()"
}

func externalReasonLine(reasons []string) string {
	if len(reasons) == 0 {
		return "Performs likely external operation"
	}
	hasHTTP := false
	hasDB := false
	hasQueue := false
	hasRPC := false
	detail := ""

	for _, reason := range reasons {
		r := strings.TrimSpace(reason)
		switch r {
		case "Do", "http.Do", "http.Client.Do":
			hasHTTP = true
			detail = "http.Client.Do"
		case "http.Get":
			hasHTTP = true
			detail = "http.Get"
		case "http.Post":
			hasHTTP = true
			detail = "http.Post"
		case "ExecContext", "QueryContext", "QueryRowContext":
			hasDB = true
			detail = r
		case "Publish", "Send", "Produce", "Enqueue":
			hasQueue = true
			detail = r
		default:
			if strings.Contains(strings.ToLower(r), "client") || strings.Contains(strings.ToLower(r), "grpc") {
				hasRPC = true
			}
		}
	}

	switch {
	case hasHTTP:
		if detail == "" {
			detail = "http.Client.Do"
		}
		return "Performs likely outbound HTTP call: " + detail
	case hasDB:
		if detail == "" {
			detail = "ExecContext"
		}
		return "Performs likely database operation: " + detail
	case hasQueue:
		if detail == "" {
			detail = "Publish"
		}
		return "Performs likely queue/event operation: " + detail
	case hasRPC:
		return "Performs likely gRPC/client call"
	default:
		return "Performs likely external operation"
	}
}

func gapWhyLine(root *analyzer.RootResult, evidenceGaps []analyzer.Gap, fn *codegraph.FunctionNode, mode string, onReachablePath bool, hasExternalSignal bool, gapAlign float64) (string, bool) {
	if root == nil || len(evidenceGaps) == 0 || len(root.MergedIntervals) == 0 || !fn.HandlesError {
		return "", false
	}
	fnTokens := tokenize(fn.FuncName + " " + fn.FilePath + " " + fn.Package)
	bestScore := 0.0
	bestText := ""
	for _, gap := range evidenceGaps {
		prev, next := neighborSpanNames(gap, root.MergedIntervals)
		contextTokens := dedupeTokens(append(tokenize(prev), tokenize(next)...))
		s := overlapScore(fnTokens, contextTokens)
		if s <= bestScore || s == 0 {
			continue
		}
		bestScore = s
		dur := formatDurationShort(gap.Duration)
		suffix := ""
		switch {
		case gap.Kind == "after_last" && prev != "":
			suffix = "after " + prev
		case gap.Kind == "before_first" && next != "":
			suffix = "before " + next
		case prev != "" && next != "":
			suffix = "between " + prev + " and " + next
		}
		if mode == "instrumentation-opportunity" {
			if suffix != "" {
				bestText = "May explain the " + dur + " gap " + suffix
			} else {
				bestText = "May explain the " + dur + " gap"
			}
		} else {
			if suffix != "" {
				bestText = "Aligns with " + dur + " gap " + suffix
			} else {
				bestText = "Aligns with " + dur + " gap"
			}
		}
	}
	if bestText == "" {
		// Fallback wording when evidence is still meaningful but token overlap is weak.
		if onReachablePath && hasExternalSignal && gapAlign == 0 {
			gap := evidenceGaps[0]
			prev, next := neighborSpanNames(gap, root.MergedIntervals)
			dur := formatDurationShort(gap.Duration)
			suffix := ""
			switch {
			case gap.Kind == "after_last" && prev != "":
				suffix = "after " + prev
			case gap.Kind == "before_first" && next != "":
				suffix = "before " + next
			case prev != "" && next != "":
				suffix = "between " + prev + " and " + next
			}
			if mode == "instrumentation-opportunity" {
				if suffix != "" {
					return "May explain the " + dur + " gap " + suffix, true
				}
				return "May explain the " + dur + " gap", true
			}
			if suffix != "" {
				return "Aligns with " + dur + " gap " + suffix, true
			}
			return "Aligns with " + dur + " gap", true
		}
		return "", false
	}
	return bestText, true
}

func formatDurationShort(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}
	if d >= time.Second {
		seconds := float64(d) / float64(time.Second)
		if seconds == float64(int64(seconds)) {
			return fmt.Sprintf("%.0fs", seconds)
		}
		return fmt.Sprintf("%.2fs", seconds)
	}
	ms := d.Milliseconds()
	if ms > 0 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%dµs", d.Microseconds())
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
		if spanHasErrorSignal(sp) {
			return "error-context"
		}
	}
	return "instrumentation-opportunity"
}

func spanHasErrorSignal(sp parser.Span) bool {
	name := strings.ToLower(sp.Name)
	if strings.Contains(name, "error") || strings.Contains(name, "exception") || strings.Contains(name, "fail") {
		return true
	}
	for _, tok := range sp.MetadataTokens {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "" {
			continue
		}
		if strings.Contains(t, "error") || strings.Contains(t, "exception") || strings.Contains(t, "fail") || strings.Contains(t, "panic") || strings.Contains(t, "timeout") || t == "500" || strings.Contains(t, "5xx") {
			return true
		}
	}
	return false
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

func gapContextTokens(root *analyzer.RootResult, evidenceGaps []analyzer.Gap) []string {
	if root == nil || len(evidenceGaps) == 0 || len(root.MergedIntervals) == 0 {
		return nil
	}
	all := make([]string, 0, 8)
	for _, gap := range evidenceGaps {
		prev, next := neighborSpanNames(gap, root.MergedIntervals)
		switch strings.TrimSpace(gap.Kind) {
		case "after_last":
			if next != "" {
				all = append(all, tokenize(next)...)
			}
		case "before_first":
			if next != "" {
				all = append(all, tokenize(next)...)
			}
		default:
			if prev != "" {
				all = append(all, tokenize(prev)...)
			}
			if next != "" {
				all = append(all, tokenize(next)...)
			}
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

func directChildSpanNames(spans []parser.Span, root *analyzer.RootResult) []string {
	if root == nil {
		return nil
	}
	rootID := strings.TrimSpace(root.RootSpan.ID)
	out := make([]string, 0, 8)
	if rootID != "" {
		for _, sp := range spans {
			if strings.TrimSpace(sp.ParentID) != rootID {
				continue
			}
			name := strings.TrimSpace(sp.Name)
			if name == "" {
				continue
			}
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		for _, in := range root.MergedIntervals {
			name := strings.TrimSpace(in.SpanName)
			if name == "" {
				continue
			}
			out = append(out, name)
		}
	}
	return dedupeTokens(out)
}

func rootMetadataTokens(spans []parser.Span, root *analyzer.RootResult) []string {
	if root == nil {
		return nil
	}
	rootID := strings.TrimSpace(root.RootSpan.ID)
	if rootID == "" {
		return dedupeTokens(root.RootSpan.MetadataTokens)
	}
	for _, sp := range spans {
		if strings.TrimSpace(sp.ID) != rootID {
			continue
		}
		return dedupeTokens(sp.MetadataTokens)
	}
	return dedupeTokens(root.RootSpan.MetadataTokens)
}

func primaryGapPrevSpanTokens(root *analyzer.RootResult, evidenceGaps []analyzer.Gap) []string {
	if root == nil || len(evidenceGaps) == 0 || len(root.MergedIntervals) == 0 {
		return nil
	}
	gap := evidenceGaps[0]
	prev, _ := neighborSpanNames(gap, root.MergedIntervals)
	if strings.TrimSpace(prev) == "" {
		return nil
	}
	return tokenize(prev)
}

func primaryGapKind(evidenceGaps []analyzer.Gap) string {
	if len(evidenceGaps) == 0 {
		return ""
	}
	return strings.TrimSpace(evidenceGaps[0].Kind)
}

func selectEvidenceGaps(root *analyzer.RootResult) []analyzer.Gap {
	if root == nil || len(root.LargestGaps) == 0 {
		return nil
	}
	if root.RootDuration <= 0 {
		return []analyzer.Gap{root.LargestGaps[0]}
	}
	for _, g := range root.LargestGaps {
		if g.Duration < minGapEvidenceDuration {
			continue
		}
		r := float64(g.Duration) / float64(root.RootDuration)
		if r < minGapEvidenceRatio {
			continue
		}
		return []analyzer.Gap{g}
	}
	return []analyzer.Gap{root.LargestGaps[0]}
}

func isInternalHelperLike(fn *codegraph.FunctionNode) bool {
	tokens := tokenize(fn.FuncName + " " + fn.FilePath + " " + fn.Package)
	if len(tokens) == 0 {
		return false
	}
	helperTerms := map[string]struct{}{
		"helper": {}, "util": {}, "utils": {}, "common": {}, "internal": {}, "build": {}, "convert": {},
		"format": {}, "map": {}, "normalize": {}, "prepare": {}, "compose": {}, "calc": {},
	}
	for _, t := range tokens {
		if _, ok := helperTerms[t]; ok {
			return true
		}
	}
	return false
}

func downstreamSemanticSignal(fn *codegraph.FunctionNode, tokens []string) float64 {
	score := 0.0
	if fn.ExternalOps.Queue || fn.ExternalOps.DB || fn.ExternalOps.RPC || fn.ExternalOps.HTTP {
		score += 0.35
	}
	semanticTerms := map[string]float64{
		"retry": 0.35, "backoff": 0.35, "queue": 0.35, "storage": 0.35, "client": 0.30,
		"gateway": 0.30, "transport": 0.30, "publish": 0.30, "save": 0.25, "persist": 0.25,
		"fraud": 0.25, "order": 0.20,
	}
	for _, t := range tokens {
		if w, ok := semanticTerms[t]; ok {
			score += w
		}
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}
