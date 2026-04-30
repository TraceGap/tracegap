package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracegap/internal/output"
)

func TestParseArgs_ValidAuditJSON(t *testing.T) {
	format, file, repo, err := parseArgs([]string{"audit", "trace.json", "--format", "json"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if format != output.FormatJSON {
		t.Fatalf("expected format json, got %s", format)
	}
	if file != "trace.json" {
		t.Fatalf("expected trace.json, got %q", file)
	}
	if repo != "" {
		t.Fatalf("expected empty repo, got %q", repo)
	}
}

func TestParseArgs_MissingCommand(t *testing.T) {
	if _, _, _, err := parseArgs([]string{}); err == nil {
		t.Fatalf("expected error for missing command")
	}
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	if _, _, _, err := parseArgs([]string{"audit", "trace.json", "--wat"}); err == nil {
		t.Fatalf("expected error for unknown flag")
	}
}

func TestParseArgs_ValidAuditJSONEqualsForm(t *testing.T) {
	format, file, repo, err := parseArgs([]string{"audit", "trace.json", "--format=json"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if format != output.FormatJSON {
		t.Fatalf("expected format json, got %s", format)
	}
	if file != "trace.json" {
		t.Fatalf("expected trace.json, got %q", file)
	}
	if repo != "" {
		t.Fatalf("expected empty repo, got %q", repo)
	}
}

func TestParseArgs_ValidRepoFlag(t *testing.T) {
	format, file, repo, err := parseArgs([]string{"audit", "trace.json", "--repo", "."})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if format != output.FormatText {
		t.Fatalf("expected text format, got %s", format)
	}
	if file != "trace.json" {
		t.Fatalf("expected trace.json, got %q", file)
	}
	if repo != "." {
		t.Fatalf("expected repo '.', got %q", repo)
	}
}

func TestParseArgs_ValidRepoEqualsForm(t *testing.T) {
	_, _, repo, err := parseArgs([]string{"audit", "trace.json", "--repo=./svc"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if repo != "svc" {
		t.Fatalf("expected cleaned repo 'svc', got %q", repo)
	}
}

func TestParseArgs_MissingRepoValue(t *testing.T) {
	if _, _, _, err := parseArgs([]string{"audit", "trace.json", "--repo"}); err == nil {
		t.Fatalf("expected error for missing repo value")
	}
}

func TestParseArgs_InvalidFormat(t *testing.T) {
	if _, _, _, err := parseArgs([]string{"audit", "trace.json", "--format", "yaml"}); err == nil {
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

func TestRun_VersionFlag(t *testing.T) {
	output := captureStdout(t, func() {
		if got, want := run([]string{"--version"}), exitSuccess; got != want {
			t.Fatalf("run exit code: got %d want %d", got, want)
		}
	})

	if !strings.Contains(output, "tracegap version") {
		t.Fatalf("expected version output, got %q", output)
	}
}

func TestRun_VersionCommand(t *testing.T) {
	output := captureStdout(t, func() {
		if got, want := run([]string{"version"}), exitSuccess; got != want {
			t.Fatalf("run exit code: got %d want %d", got, want)
		}
	})

	if !strings.Contains(output, "tracegap version") {
		t.Fatalf("expected version output, got %q", output)
	}
}

func TestRun_HelpFlag(t *testing.T) {
	output := captureStdout(t, func() {
		if got, want := run([]string{"--help"}), exitSuccess; got != want {
			t.Fatalf("run exit code: got %d want %d", got, want)
		}
	})

	if !strings.Contains(output, "Commands:") {
		t.Fatalf("expected commands section in help output, got %q", output)
	}
	if !strings.Contains(output, "audit <trace.json>") {
		t.Fatalf("expected audit description in help output, got %q", output)
	}
}

func TestRun_HelpCommand(t *testing.T) {
	output := captureStdout(t, func() {
		if got, want := run([]string{"help"}), exitSuccess; got != want {
			t.Fatalf("run exit code: got %d want %d", got, want)
		}
	})

	if !strings.Contains(output, "--help, -h, help") {
		t.Fatalf("expected help aliases in output, got %q", output)
	}
}

func TestRun_CheckoutFixtureRepoAnalysisModes(t *testing.T) {
	repo := filepath.Join("..", "..", "examples", "checkout-go")
	errorTrace := filepath.Join(repo, "traces", "checkout-error.json")
	successTrace := filepath.Join(repo, "traces", "checkout-success.json")

	errorOutput := captureStdout(t, func() {
		if got, want := run([]string{"audit", errorTrace, "--repo", repo}), exitSuccess; got != want {
			t.Fatalf("error trace run exit code: got %d want %d", got, want)
		}
	})
	if !strings.Contains(errorOutput, "Repo Analysis (Go)") {
		t.Fatalf("expected go repo analysis heading, got %q", errorOutput)
	}
	if !strings.Contains(errorOutput, "Most suspicious uninstrumented code paths:") {
		t.Fatalf("expected suspicious paths heading, got %q", errorOutput)
	}
	if !strings.Contains(errorOutput, "Start here:") {
		t.Fatalf("expected Start here action label for error mode, got %q", errorOutput)
	}
	if !strings.Contains(errorOutput, "internal/payment/client.go") {
		t.Fatalf("expected payment client candidate in error output, got %q", errorOutput)
	}

	successOutput := captureStdout(t, func() {
		if got, want := run([]string{"audit", successTrace, "--repo", repo}), exitSuccess; got != want {
			t.Fatalf("success trace run exit code: got %d want %d", got, want)
		}
	})
	if !strings.Contains(successOutput, "Likely instrumentation opportunities:") {
		t.Fatalf("expected instrumentation opportunities heading, got %q", successOutput)
	}
	if !strings.Contains(successOutput, "Consider:") {
		t.Fatalf("expected Consider action label for success mode, got %q", successOutput)
	}
	if !strings.Contains(successOutput, "internal/payment/client.go") {
		t.Fatalf("expected payment client candidate in success output, got %q", successOutput)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = original

	bytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}
	_ = r.Close()

	return string(bytes)
}
