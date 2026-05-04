package analyzer

import (
	"strings"

	"tracegap/internal/parser"
)

type AsyncInsight struct {
	Detected                bool
	PrimaryRootName         string
	SecondaryRootName       string
	SecondaryClassification string
	PrimaryEndsEarly        bool
}

type rootKind int

const (
	rootKindUnknown rootKind = iota
	rootKindWeb
	rootKindAsync
)

const primaryEndsEarlyRatio = 0.1

var asyncStrongTokens = []string{
	"consume", "consumer", "consuming",
	"stream", "streaming",
	"queue", "queues",
	"worker", "workers",
	"subscribe", "subscriber", "subscription",
	"kafka", "rabbitmq", "sqs", "pubsub", "messaging",
}

var asyncWeakTokens = []string{"event", "handler"}

var webTokens = []string{
	"web", "server",
	"http", "https",
	"request",
	"api",
	"get", "post", "put", "delete", "patch",
	"route",
}

func detectAsyncInsight(results []RootResult) AsyncInsight {
	if len(results) < 2 {
		return AsyncInsight{}
	}

	var primary *RootResult
	var secondary *RootResult
	var secondaryClass string

	for i := range results {
		r := &results[i]
		if classifyRoot(r.RootSpan) == rootKindWeb {
			primary = r
			break
		}
	}
	if primary == nil {
		return AsyncInsight{}
	}

	for i := range results {
		r := &results[i]
		if r.RootSpan.ID == primary.RootSpan.ID {
			continue
		}
		if classifyRoot(r.RootSpan) == rootKindAsync {
			secondary = r
			secondaryClass = asyncClassification(r.RootSpan)
			break
		}
	}
	if secondary == nil {
		return AsyncInsight{}
	}

	endsEarly := false
	if primary.RootDuration > 0 {
		for _, gap := range primary.LargestGaps {
			if gap.Kind != "after_last" || gap.Duration <= 0 {
				continue
			}
			if float64(gap.Duration)/float64(primary.RootDuration) > primaryEndsEarlyRatio {
				endsEarly = true
				break
			}
		}
	}

	return AsyncInsight{
		Detected:                true,
		PrimaryRootName:         primary.RootSpan.Name,
		SecondaryRootName:       secondary.RootSpan.Name,
		SecondaryClassification: secondaryClass,
		PrimaryEndsEarly:        endsEarly,
	}
}

func classifyRoot(span parser.Span) rootKind {
	tokens := tokenSet(span)
	if anyTokenMatches(tokens, asyncStrongTokens) {
		return rootKindAsync
	}
	if anyTokenMatches(tokens, webTokens) || strings.Contains(span.Name, "/") {
		return rootKindWeb
	}
	if anyTokenMatches(tokens, asyncWeakTokens) {
		return rootKindAsync
	}
	return rootKindUnknown
}

func asyncClassification(span parser.Span) string {
	tokens := tokenSet(span)
	switch {
	case hasToken(tokens, "consume") || hasToken(tokens, "consumer") || hasToken(tokens, "consuming") || hasToken(tokens, "subscribe") || hasToken(tokens, "subscriber"):
		return "worker/consumer work"
	case hasToken(tokens, "stream") || hasToken(tokens, "streaming") || hasToken(tokens, "kafka") || hasToken(tokens, "pubsub") || hasToken(tokens, "messaging"):
		return "stream/messaging work"
	case hasToken(tokens, "queue") || hasToken(tokens, "queues") || hasToken(tokens, "rabbitmq") || hasToken(tokens, "sqs"):
		return "queue work"
	case hasToken(tokens, "worker") || hasToken(tokens, "workers"):
		return "worker/consumer work"
	default:
		return "async/event work"
	}
}

func tokenSet(span parser.Span) map[string]struct{} {
	set := make(map[string]struct{}, len(span.MetadataTokens)+4)
	for _, t := range span.MetadataTokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		set[t] = struct{}{}
	}
	for _, t := range splitName(span.Name) {
		set[t] = struct{}{}
	}
	return set
}

func splitName(name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil
	}
	repl := strings.NewReplacer("/", " ", "-", " ", "_", " ", ".", " ", ":", " ", "{", " ", "}", " ")
	parts := strings.Fields(repl.Replace(name))
	return parts
}

func anyTokenMatches(tokens map[string]struct{}, candidates []string) bool {
	for _, c := range candidates {
		if _, ok := tokens[c]; ok {
			return true
		}
	}
	return false
}

func hasToken(tokens map[string]struct{}, t string) bool {
	_, ok := tokens[t]
	return ok
}
