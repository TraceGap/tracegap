package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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

func ParseFile(path string) ([]Span, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read trace file: %w", err)
	}

	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	spans := make([]Span, 0, 128)
	walkAndCollect(root, &spans)
	return dedupeByID(spans), nil
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
		}
	}
	return ""
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
