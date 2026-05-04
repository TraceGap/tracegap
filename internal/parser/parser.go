package parser

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type SchemaType string

const (
	SchemaOTLP    SchemaType = "otlp"
	SchemaJaeger  SchemaType = "jaeger"
	SchemaDatadog SchemaType = "datadog"
	SchemaUnknown SchemaType = "unknown"
)

// Span is the normalized representation used by analysis code.
type Span struct {
	ID       string
	ParentID string
	Name     string
	Start    time.Time
	End      time.Time
	HasStart bool
	HasEnd   bool
	MetadataTokens []string
}

func (s Span) HasTimestamps() bool {
	return s.HasStart && s.HasEnd && s.End.After(s.Start)
}

func (s Span) Duration() time.Duration {
	if !s.HasTimestamps() {
		return 0
	}
	return s.End.Sub(s.Start)
}

func ParseFile(path string) ([]Span, SchemaType, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, SchemaUnknown, fmt.Errorf("failed to read trace file: %w", err)
	}

	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, SchemaUnknown, fmt.Errorf("failed to parse JSON: %w", err)
	}

	schema := detectSchema(root)
	var spans []Span
	switch schema {
	case SchemaOTLP:
		spans = parseOTLP(root)
	case SchemaJaeger:
		spans = parseJaeger(root)
	case SchemaDatadog:
		spans = parseDatadog(root)
	default:
		return nil, SchemaUnknown, fmt.Errorf("unsupported trace schema: expected OTLP, Jaeger, or Datadog JSON")
	}
	return dedupeByID(spans), schema, nil
}

func detectSchema(root any) SchemaType {
	if looksLikeDatadogRoot(root) {
		return SchemaDatadog
	}
	m, ok := root.(map[string]any)
	if !ok {
		return SchemaUnknown
	}
	if _, ok := m["resourceSpans"]; ok {
		return SchemaOTLP
	}
	if _, ok := m["data"]; ok {
		return SchemaJaeger
	}
	return SchemaUnknown
}

func parseOTLP(root any) []Span {
	m, ok := root.(map[string]any)
	if !ok {
		spans := make([]Span, 0, 128)
		walkAndCollect(root, &spans)
		return spans
	}
	resourceSpans, ok := m["resourceSpans"].([]any)
	if !ok {
		spans := make([]Span, 0, 128)
		walkAndCollect(root, &spans)
		return spans
	}
	out := make([]Span, 0, 128)
	for _, rsRaw := range resourceSpans {
		rs, ok := rsRaw.(map[string]any)
		if !ok {
			continue
		}
		resourceTokens := otlpResourceTokens(rs)
		scopeSpans, ok := rs["scopeSpans"].([]any)
		if !ok {
			continue
		}
		for _, ssRaw := range scopeSpans {
			ss, ok := ssRaw.(map[string]any)
			if !ok {
				continue
			}
			spansAny, ok := ss["spans"].([]any)
			if !ok {
				continue
			}
			for _, rawSpan := range spansAny {
				spanMap, ok := rawSpan.(map[string]any)
				if !ok {
					continue
				}
				span, parsed := tryParseSpan(spanMap)
				if !parsed {
					continue
				}
				span.MetadataTokens = dedupeTokens(append(span.MetadataTokens, resourceTokens...))
				out = append(out, span)
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	spans := make([]Span, 0, 128)
	walkAndCollect(root, &spans)
	return spans
}

func parseJaeger(root any) []Span {
	m, ok := root.(map[string]any)
	if !ok {
		return nil
	}
	data, ok := m["data"].([]any)
	if !ok {
		return nil
	}
	out := make([]Span, 0, 128)
	for _, entry := range data {
		traceObj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		spansAny, ok := traceObj["spans"].([]any)
		if !ok {
			continue
		}
		for _, rawSpan := range spansAny {
			spanMap, ok := rawSpan.(map[string]any)
			if !ok {
				continue
			}
			id := getString(spanMap, "spanID", "spanId", "span_id", "id")
			if id == "" {
				continue
			}
			span := Span{
				ID:       id,
				ParentID: parentIDFromJaegerRefs(spanMap),
				Name:     getString(spanMap, "operationName", "name"),
				MetadataTokens: jaegerMetadataTokens(spanMap),
			}
			if span.Name == "" {
				span.Name = span.ID
			}
			if startMicro, ok := getInt64(spanMap, "startTime"); ok {
				span.Start = time.Unix(0, startMicro*int64(time.Microsecond))
				span.HasStart = true
				if durMicro, ok := getInt64(spanMap, "duration"); ok && durMicro >= 0 {
					span.End = span.Start.Add(time.Duration(durMicro) * time.Microsecond)
					span.HasEnd = true
				}
			}
			out = append(out, span)
		}
	}
	return out
}

func parseDatadog(root any) []Span {
	traces := datadogTraceEntries(root)
	if len(traces) == 0 {
		return nil
	}
	out := make([]Span, 0, 128)
	for _, traceEntry := range traces {
		traceSpans, ok := traceEntry.([]any)
		if !ok {
			continue
		}
		if !looksLikeDatadogSpanArray(traceSpans) {
			continue
		}
		for _, raw := range traceSpans {
			spanMap, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			id := getString(spanMap, "span_id", "spanId", "spanID", "id")
			if id == "" {
				continue
			}
			parentID := getString(spanMap, "parent_id", "parentId", "parentID", "parent_span_id")
			if parentID == "0" {
				parentID = ""
			}
			name := getString(spanMap, "name", "resource")
			if name == "" {
				name = id
			}

			span := Span{ID: id, ParentID: parentID, Name: name, MetadataTokens: datadogMetadataTokens(spanMap)}
			if startRaw, ok := getInt64(spanMap, "start", "start_ns", "startTime"); ok {
				start := epochWithUnitGuess(startRaw)
				span.Start = start
				span.HasStart = true
				if durRaw, ok := getInt64(spanMap, "duration", "duration_ns"); ok && durRaw >= 0 {
					span.End = start.Add(durationWithUnitGuess(durRaw, startRaw))
					span.HasEnd = true
				}
			}
			out = append(out, span)
		}
	}
	return out
}

func looksLikeDatadogRoot(root any) bool {
	entries := datadogTraceEntries(root)
	for _, entry := range entries {
		traceSpans, ok := entry.([]any)
		if !ok {
			continue
		}
		if looksLikeDatadogSpanArray(traceSpans) {
			return true
		}
	}
	return false
}

func datadogTraceEntries(root any) []any {
	switch v := root.(type) {
	case map[string]any:
		if traces, ok := v["traces"].([]any); ok {
			if looksLikeDatadogSpanArray(traces) {
				// Flat span list under "traces": treat as a single trace.
				return []any{traces}
			}
			return traces
		}
		return nil
	case []any:
		if looksLikeDatadogSpanArray(v) {
			// Flat top-level span list: treat as a single trace.
			return []any{v}
		}
		return v
	default:
		return nil
	}
}

func looksLikeDatadogSpanArray(items []any) bool {
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		span, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if looksLikeDatadogSpanObject(span) {
			return true
		}
	}
	return false
}

func looksLikeDatadogSpanObject(span map[string]any) bool {
	if span == nil {
		return false
	}
	if hasAnyKey(span, "span_id", "spanId", "spanID", "id") && hasAnyKey(span, "trace_id", "traceId", "traceID") {
		return true
	}
	if hasAnyKey(span, "span_id", "spanId", "spanID", "id") && hasAnyKey(span, "start", "start_ns", "startTime") {
		return true
	}
	if hasAnyKey(span, "span_id", "spanId", "spanID", "id") && hasAnyKey(span, "duration", "duration_ns") {
		return true
	}
	return false
}

func hasAnyKey(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func parentIDFromJaegerRefs(span map[string]any) string {
	refs, ok := span["references"].([]any)
	if !ok {
		return ""
	}
	for _, ref := range refs {
		m, ok := ref.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(getString(m, "refType", "type"), "CHILD_OF") {
			return getString(m, "spanID", "spanId", "span_id")
		}
	}
	return ""
}

func walkAndCollect(node any, out *[]Span) {
	switch v := node.(type) {
	case map[string]any:
		if span, ok := tryParseSpan(v); ok {
			*out = append(*out, span)
		}
		for _, child := range v {
			walkAndCollect(child, out)
		}
	case []any:
		for _, item := range v {
			walkAndCollect(item, out)
		}
	}
}

func tryParseSpan(m map[string]any) (Span, bool) {
	id := getString(m, "spanId", "span_id", "id")
	if id == "" {
		return Span{}, false
	}

	span := Span{
		ID:       id,
		ParentID: getString(m, "parentSpanId", "parent_span_id", "parentId", "parent_id"),
		Name:     getString(m, "name"),
		MetadataTokens: otlpSpanMetadataTokens(m),
	}
	if span.Name == "" {
		span.Name = span.ID
	}

	if t, ok := getTimestamp(m, "startTimeUnixNano", "start_time_unix_nano", "startTime", "start"); ok {
		span.Start = t
		span.HasStart = true
	}
	if t, ok := getTimestamp(m, "endTimeUnixNano", "end_time_unix_nano", "endTime", "end"); ok {
		span.End = t
		span.HasEnd = true
	}

	return span, true
}

func otlpResourceTokens(resourceSpan map[string]any) []string {
	resource, ok := resourceSpan["resource"].(map[string]any)
	if !ok {
		return nil
	}
	attrs, ok := resource["attributes"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, 8)
	for _, raw := range attrs {
		attr, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		key := strings.TrimSpace(getString(attr, "key"))
		if key == "" {
			continue
		}
		if !isMetadataKey(key) {
			continue
		}
		valueObj, _ := attr["value"].(map[string]any)
		for _, vk := range []string{"stringValue", "value"} {
			if v := strings.TrimSpace(getString(valueObj, vk)); v != "" {
				out = append(out, tokenize(v)...)
			}
		}
	}
	return dedupeTokens(out)
}

func otlpSpanMetadataTokens(span map[string]any) []string {
	out := make([]string, 0, 10)
	for _, k := range []string{"name", "resource", "service", "http.route", "url.path", "http.url"} {
		if v := strings.TrimSpace(getString(span, k)); v != "" {
			out = append(out, tokenize(v)...)
		}
	}
	if attrs, ok := span["attributes"].([]any); ok {
		for _, raw := range attrs {
			attr, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			key := strings.TrimSpace(getString(attr, "key"))
			if !isMetadataKey(key) {
				continue
			}
			valueObj, _ := attr["value"].(map[string]any)
			if v := strings.TrimSpace(getString(valueObj, "stringValue", "value")); v != "" {
				out = append(out, tokenize(v)...)
			}
		}
	}
	return dedupeTokens(out)
}

func datadogMetadataTokens(span map[string]any) []string {
	out := make([]string, 0, 12)
	for _, k := range []string{"name", "resource", "service", "type"} {
		if v := strings.TrimSpace(getString(span, k)); v != "" {
			out = append(out, tokenize(v)...)
		}
	}
	if meta, ok := span["meta"].(map[string]any); ok {
		for key, val := range meta {
			if !isMetadataKey(key) {
				continue
			}
			if s, ok := val.(string); ok {
				out = append(out, tokenize(s)...)
			}
		}
	}
	return dedupeTokens(out)
}

func jaegerMetadataTokens(span map[string]any) []string {
	out := make([]string, 0, 10)
	for _, k := range []string{"operationName", "name", "serviceName", "resource"} {
		if v := strings.TrimSpace(getString(span, k)); v != "" {
			out = append(out, tokenize(v)...)
		}
	}
	if tags, ok := span["tags"].([]any); ok {
		for _, raw := range tags {
			tag, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			key := strings.TrimSpace(getString(tag, "key"))
			if !isMetadataKey(key) {
				continue
			}
			if v := strings.TrimSpace(getString(tag, "value", "vStr", "vstr")); v != "" {
				out = append(out, tokenize(v)...)
			}
		}
	}
	return dedupeTokens(out)
}

func isMetadataKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if strings.Contains(k, "service") || strings.Contains(k, "resource") || strings.Contains(k, "route") || strings.Contains(k, "url") || strings.Contains(k, "path") {
		return true
	}
	return false
}

func tokenize(s string) []string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	repl := strings.NewReplacer("/", " ", "-", " ", "_", " ", ".", " ", ":", " ", "{", " ", "}", " ")
	s = repl.Replace(s)
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return dedupeTokens(out)
}

func dedupeTokens(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		set[t] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out
}

func getString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		value, ok := m[k]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed != "" {
				return trimmed
			}
		case float64:
			return strconv.FormatInt(int64(v), 10)
		case int64:
			return strconv.FormatInt(v, 10)
		}
	}
	return ""
}

func getInt64(m map[string]any, keys ...string) (int64, bool) {
	for _, k := range keys {
		value, ok := m[k]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			return int64(v), true
		case string:
			s := strings.TrimSpace(v)
			if s == "" {
				continue
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func epochWithUnitGuess(v int64) time.Time {
	if v <= 0 {
		return time.Unix(0, 0)
	}
	// Keep this simple for MVP: very old/small epochs are likely micros.
	if v < 1_000_000_000_000_000 {
		return time.Unix(0, v*int64(time.Microsecond))
	}
	return time.Unix(0, v)
}

func durationWithUnitGuess(durationRaw, startRaw int64) time.Duration {
	if durationRaw < 0 {
		return 0
	}
	if startRaw < 1_000_000_000_000_000 {
		return time.Duration(durationRaw) * time.Microsecond
	}
	return time.Duration(durationRaw)
}

func getTimestamp(m map[string]any, keys ...string) (time.Time, bool) {
	for _, k := range keys {
		value, ok := m[k]
		if !ok || value == nil {
			continue
		}
		if ts, ok := parseTimestamp(value); ok {
			return ts, true
		}
	}
	return time.Time{}, false
}

func parseTimestamp(value any) (time.Time, bool) {
	switch v := value.(type) {
	case float64:
		n := int64(v)
		if n < 0 {
			return time.Time{}, false
		}
		return time.Unix(0, n), true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return time.Time{}, false
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
			return time.Unix(0, n), true
		}
		layouts := []string{time.RFC3339Nano, time.RFC3339}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func dedupeByID(spans []Span) []Span {
	seen := make(map[string]struct{}, len(spans))
	out := make([]Span, 0, len(spans))
	for _, s := range spans {
		if _, ok := seen[s.ID]; ok {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	return out
}
