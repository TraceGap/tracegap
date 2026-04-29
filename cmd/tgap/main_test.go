package main

import (
	"os"
	"path/filepath"
	"testing"

	"tracegap/internal/output"
)

func TestParseArgs_ValidAuditJSON(t *testing.T) {
	format, file, err := parseArgs([]string{"audit", "trace.json", "--format", "json"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if format != output.FormatJSON {
		t.Fatalf("expected format json, got %s", format)
	}
	if file != "trace.json" {
		t.Fatalf("expected trace.json, got %q", file)
	}
}

func TestParseArgs_MissingCommand(t *testing.T) {
	if _, _, err := parseArgs([]string{}); err == nil {
		t.Fatalf("expected error for missing command")
	}
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	if _, _, err := parseArgs([]string{"audit", "trace.json", "--wat"}); err == nil {
		t.Fatalf("expected error for unknown flag")
	}
}

func TestParseArgs_ValidAuditJSONEqualsForm(t *testing.T) {
	format, file, err := parseArgs([]string{"audit", "trace.json", "--format=json"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if format != output.FormatJSON {
		t.Fatalf("expected format json, got %s", format)
	}
	if file != "trace.json" {
		t.Fatalf("expected trace.json, got %q", file)
	}
}

func TestParseArgs_InvalidFormat(t *testing.T) {
	if _, _, err := parseArgs([]string{"audit", "trace.json", "--format", "yaml"}); err == nil {
		t.Fatalf("expected invalid format error")
	}
}

func TestRun_MissingFileArgExitCode2(t *testing.T) {
	if got, want := run([]string{"audit"}), exitInvalidInput; got != want {
		t.Fatalf("run exit code: got %d want %d", got, want)
	}
}

func TestRun_NoSpansExitCode0(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"resourceSpans":[]}`), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if got, want := run([]string{"audit", path}), exitSuccess; got != want {
		t.Fatalf("run exit code: got %d want %d", got, want)
	}
}

func TestRun_InvalidJSONExitCode1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{bad json}"), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if got, want := run([]string{"audit", path}), exitRuntimeError; got != want {
		t.Fatalf("run exit code: got %d want %d", got, want)
	}
}

func TestRun_SupportedSchemaFixtures(t *testing.T) {
	fixtures := []string{
		filepath.Join("..", "..", "internal", "parser", "testdata", "trace.json"),
		filepath.Join("..", "..", "internal", "parser", "testdata", "jaeger.json"),
		filepath.Join("..", "..", "internal", "parser", "testdata", "datadog.json"),
		filepath.Join("..", "..", "internal", "parser", "testdata", "grafana_otlp.json"),
		filepath.Join("..", "..", "internal", "parser", "testdata", "grafana_jaeger.json"),
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			if got, want := run([]string{"audit", fixture}), exitSuccess; got != want {
				t.Fatalf("run exit code for %s: got %d want %d", fixture, got, want)
			}
		})
	}
}

func TestRun_UnknownSchemaExitCode1(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "parser", "testdata", "unknown.json")
	if got, want := run([]string{"audit", fixture}), exitRuntimeError; got != want {
		t.Fatalf("run exit code: got %d want %d", got, want)
	}
}
