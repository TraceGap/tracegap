package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tracegap/internal/analyzer"
	"tracegap/internal/output"
	"tracegap/internal/parser"
	"tracegap/internal/repoanalysis"
)

const (
	exitSuccess      = 0
	exitRuntimeError = 1
	exitInvalidInput = 2
)

var version = "dev"

func main() {
	exitCode := run(os.Args[1:])
	os.Exit(exitCode)
}

func run(args []string) int {
	if isHelpCommand(args) {
		printHelp(os.Stdout)
		return exitSuccess
	}

	if isVersionCommand(args) {
		printVersion(os.Stdout)
		return exitSuccess
	}

	format, traceFile, repoPath, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		printUsage(os.Stderr)
		return exitInvalidInput
	}

	if traceFile == "" {
		fmt.Fprintln(os.Stderr, "Nothing to audit. Provide a trace JSON file.")
		printUsage(os.Stderr)
		printNoFileHelp(os.Stderr)
		return exitInvalidInput
	}

	spans, schema, err := parser.ParseFile(traceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to audit trace file: %v\n", err)
		return exitRuntimeError
	}

	if len(spans) == 0 {
		output.PrintNoSpans(os.Stdout)
		return exitSuccess
	}

	analysis := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)
	analysis.DetectedSchema = string(schema)

	var repoResult *repoanalysis.Result
	if format == output.FormatText && strings.TrimSpace(repoPath) != "" {
		repoResult, err = repoanalysis.Analyze(repoPath, analysis, spans)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: repo analysis skipped: %v\n", err)
		} else if repoResult != nil && repoResult.Mode != "error-context" && traceFileHasErrorSignal(traceFile) {
			// Fallback for traces whose parsed spans don't carry explicit error tokens.
			repoResult.Mode = "error-context"
		}
	}
	switch format {
	case output.FormatText:
		output.PrintAuditText(os.Stdout, analysis)
		output.PrintRepoAnalysisText(os.Stdout, repoResult)
	case output.FormatJSON:
		if err := output.PrintAuditJSON(os.Stdout, analysis, traceFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to render output: %v\n", err)
			return exitRuntimeError
		}
	default:
		fmt.Fprintf(os.Stderr, "Unsupported format: %s\n", format)
		return exitInvalidInput
	}

	return exitSuccess
}

func parseArgs(args []string) (output.Format, string, string, error) {
	if len(args) == 0 {
		return output.FormatText, "", "", errors.New("missing command")
	}
	if args[0] != "audit" {
		return output.FormatText, "", "", fmt.Errorf("unsupported command: %s", args[0])
	}

	format := output.FormatText
	traceFile := ""
	repoPath := ""
	tokens := args[1:]

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok == "--format":
			if i+1 >= len(tokens) {
				return output.FormatText, "", "", errors.New("missing value for --format")
			}
			format = output.Format(strings.ToLower(strings.TrimSpace(tokens[i+1])))
			i++
		case tok == "--repo":
			if i+1 >= len(tokens) {
				return output.FormatText, "", "", errors.New("missing value for --repo")
			}
			repoPath = strings.TrimSpace(tokens[i+1])
			i++
		case strings.HasPrefix(tok, "--format="):
			value := strings.TrimSpace(strings.TrimPrefix(tok, "--format="))
			format = output.Format(strings.ToLower(value))
		case strings.HasPrefix(tok, "--repo="):
			repoPath = strings.TrimSpace(strings.TrimPrefix(tok, "--repo="))
		case strings.HasPrefix(tok, "-"):
			return output.FormatText, "", "", fmt.Errorf("unknown flag: %s", tok)
		default:
			if traceFile != "" {
				return output.FormatText, "", "", errors.New("expected a single trace JSON file")
			}
			traceFile = tok
		}
	}

	if format != output.FormatText && format != output.FormatJSON {
		return output.FormatText, "", "", fmt.Errorf("invalid format %q (allowed: text, json)", format)
	}
	if traceFile != "" {
		traceFile = filepath.Clean(traceFile)
	}
	if repoPath != "" {
		repoPath = filepath.Clean(repoPath)
	}
	return format, traceFile, repoPath, nil
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tgap audit trace.json")
	fmt.Fprintln(w, "  tgap audit trace.json --format json")
	fmt.Fprintln(w, "  tgap audit trace.json --repo .")
	fmt.Fprintln(w, "  tgap --version")
	fmt.Fprintln(w, "  tgap --help")
	fmt.Fprintln(w, "  tracegap audit trace.json")
	fmt.Fprintln(w, "  tracegap audit trace.json --format json")
	fmt.Fprintln(w, "  tracegap audit trace.json --repo .")
	fmt.Fprintln(w, "  tracegap --version")
	fmt.Fprintln(w, "  tracegap --help")
}

func printHelp(w *os.File) {
	fmt.Fprintln(w, "TraceGap CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  audit <trace.json>                 Audit trace coverage (text output)")
	fmt.Fprintln(w, "  audit <trace.json> --format json   Audit trace coverage (JSON output)")
	fmt.Fprintln(w, "  audit <trace.json> --repo <path>   Add local repo-aware analysis")
	fmt.Fprintln(w, "  --version, -v, version             Print CLI version")
	fmt.Fprintln(w, "  --help, -h, help                   Show this help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Executable aliases:")
	fmt.Fprintln(w, "  tgap")
	fmt.Fprintln(w, "  tracegap")
}

func printNoFileHelp(w *os.File) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To get started:")
	fmt.Fprintln(w, "  Export a trace as JSON (OTLP/Jaeger) and run:")
	fmt.Fprintln(w, "  tgap audit <trace.json>")
	fmt.Fprintln(w, "  tracegap audit <trace.json>")
}

func isVersionCommand(args []string) bool {
	if len(args) != 1 {
		return false
	}
	return args[0] == "--version" || args[0] == "-v" || args[0] == "version"
}

func isHelpCommand(args []string) bool {
	if len(args) != 1 {
		return false
	}
	return args[0] == "--help" || args[0] == "-h" || args[0] == "help"
}

func printVersion(w *os.File) {
	fmt.Fprintf(w, "tracegap version %s\n", version)
}

func traceFileHasErrorSignal(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return false
	}
	return jsonHasErrorSignal(root, false)
}

func jsonHasErrorSignal(node any, inStatus bool) bool {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			k := strings.ToLower(strings.TrimSpace(key))
			nextInStatus := inStatus || k == "status"

			if isErrorBoolKey(k) && truthyJSONValue(val) {
				return true
			}
			if isHTTPStatusKey(k) {
				if n, ok := intFromJSONValue(val); ok && n >= 500 {
					return true
				}
			}
			if inStatus && k == "code" {
				if statusCodeIndicatesError(val) {
					return true
				}
			}
			if inStatus && k == "message" {
				s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
				if strings.Contains(s, "error") || strings.Contains(s, "exception") || strings.Contains(s, "fail") {
					return true
				}
			}

			if jsonHasErrorSignal(val, nextInStatus) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if jsonHasErrorSignal(item, inStatus) {
				return true
			}
		}
	}
	return false
}

func isErrorBoolKey(key string) bool {
	switch key {
	case "error", "is_error", "errored":
		return true
	default:
		return false
	}
}

func isHTTPStatusKey(key string) bool {
	switch key {
	case "http.status_code", "status_code", "statuscode", "httpstatuscode":
		return true
	default:
		return false
	}
}

func statusCodeIndicatesError(v any) bool {
	if n, ok := intFromJSONValue(v); ok {
		// OTLP status.code uses 2 for error.
		if n >= 2 {
			return true
		}
	}
	s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
	return s == "status_code_error" || s == "error"
}

func truthyJSONValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

func intFromJSONValue(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
