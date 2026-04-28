package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tracegap/internal/analyzer"
	"tracegap/internal/output"
	"tracegap/internal/parser"
)

const (
	exitSuccess      = 0
	exitRuntimeError = 1
	exitInvalidInput = 2
)

func main() {
	exitCode := run(os.Args[1:])
	os.Exit(exitCode)
}

func run(args []string) int {
	format, traceFile, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		printUsage(os.Stderr)
		return exitInvalidInput
	}

	if traceFile == "" {
		fmt.Fprintln(os.Stderr, "Nothing to audit. Provide a trace JSON file.")
		printUsage(os.Stderr)
		return exitInvalidInput
	}

	spans, err := parser.ParseFile(traceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to audit trace file: %v\n", err)
		return exitRuntimeError
	}

	if len(spans) == 0 {
		output.PrintNoSpans(os.Stdout)
		return exitSuccess
	}

	analysis := analyzer.Analyze(spans, analyzer.DefaultTimelineWidth)
	switch format {
	case output.FormatText:
		output.PrintAuditText(os.Stdout, analysis)
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

func parseArgs(args []string) (output.Format, string, error) {
	if len(args) == 0 {
		return output.FormatText, "", errors.New("missing command")
	}
	if args[0] != "audit" {
		return output.FormatText, "", fmt.Errorf("unsupported command: %s", args[0])
	}

	format := output.FormatText
	traceFile := ""
	tokens := args[1:]

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok == "--format":
			if i+1 >= len(tokens) {
				return output.FormatText, "", errors.New("missing value for --format")
			}
			format = output.Format(strings.ToLower(strings.TrimSpace(tokens[i+1])))
			i++
		case strings.HasPrefix(tok, "--format="):
			value := strings.TrimSpace(strings.TrimPrefix(tok, "--format="))
			format = output.Format(strings.ToLower(value))
		case strings.HasPrefix(tok, "-"):
			return output.FormatText, "", fmt.Errorf("unknown flag: %s", tok)
		default:
			if traceFile != "" {
				return output.FormatText, "", errors.New("expected a single trace JSON file")
			}
			traceFile = tok
		}
	}

	if format != output.FormatText && format != output.FormatJSON {
		return output.FormatText, "", fmt.Errorf("invalid format %q (allowed: text, json)", format)
	}
	if traceFile != "" {
		traceFile = filepath.Clean(traceFile)
	}
	return format, traceFile, nil
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tgap audit trace.json")
	fmt.Fprintln(w, "  tgap audit trace.json --format json")
}
