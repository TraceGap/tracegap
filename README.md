# TraceGap

Find the missing time in your distributed traces.

TraceGap is a local CLI that audits a single exported trace and shows how much request time is not explained by child spans.

## Installation

### Homebrew (macOS)

```bash
brew tap tracegap/tap
brew install tracegap
tracegap audit path/to/trace.json
```

This installs both `tracegap` and the shorter alias `tgap`.

## Sample Output

```text
TraceGap Audit
Schema: OTLP
Root span: checkout.request (1s)
⚠️ A significant portion of this request is not traced (50% missing)
Trace coverage: 50%
Unaccounted time: 50% (500ms)
Largest gaps:
1. 700ms–1s (300ms) after inventory
2. 200ms–400ms (200ms) between auth and inventory
checkout.request (1s)
██████auth██████················███████inventory████████························
covered: 500ms | gap: 500ms
```

## Local-Only By Design

- No backend
- No network calls
- No auth
- No config files

## What It Analyzes

Given a trace JSON file (OpenTelemetry-style or similar), TraceGap:

1. Parses spans and normalizes:
   - span ID
   - parent span ID
   - start timestamp
   - end timestamp
   - span name
2. Identifies root spans.
3. For each root span, collects direct child intervals.
4. Sorts and merges overlapping child intervals.
5. Computes:
   - coverage percent
   - unaccounted time
   - largest gaps (top 3-5)
6. Renders a timeline bar per root span.
7. Prints probabilistic remediation guidance.

## Supported Import Schemas

TraceGap auto-detects and parses these trace JSON schema families:

- OTLP JSON
- Jaeger JSON
- Datadog trace JSON
- Grafana-compatible exports that are OTLP-shaped or Jaeger-shaped

On successful parse, output includes the detected schema.

Example:

```text
TraceGap Audit
Schema: OTLP
```

## OTLP JSON Alignment

Examples in this repo are aligned to OTLP/JSON conventions:

- lowerCamelCase field names (for example resourceSpans, scopeSpans, startTimeUnixNano)
- traceId as 32 hex chars
- spanId and parentSpanId as 16 hex chars
- 64-bit timestamps encoded as decimal strings

TraceGap is intentionally tolerant and can parse OTLP-style variants, but canonical OTLP JSON is recommended for sample files.

## JSON Output Example

```bash
tgap audit trace.json --format json
tgap audit trace.json --repo .
# alias command works too
tracegap audit trace.json --format json
tracegap audit trace.json --repo .
```

Returns structured output including:

- summary coverage and unaccounted time
- per-root metrics
- largest gaps
- timeline bar
- likely causes and recommended checks

## Missing Timestamps Behavior

If timestamps are missing, TraceGap does not infer positional gaps.

It reports aggregate-only analysis when possible and clearly states that positional analysis is unavailable.

## Exit Codes

- 0: success
- 1: runtime error
- 2: invalid input or missing args

Missing input behavior:

```text
Nothing to audit. Provide a trace JSON file.
Usage:
  tgap audit trace.json
  tgap audit trace.json --format json
  tgap --version
  tgap --help
  tracegap audit trace.json
  tracegap audit trace.json --format json
  tracegap --version
  tracegap --help

To get started:
  Export a trace as JSON (OTLP/Jaeger) and run:
  tgap audit <trace.json>
  tracegap audit <trace.json>
```

## Development

Run tests:

```bash
make test
```

Run analyzer benchmarks:

```bash
make benchmark
```

Run static checks:

```bash
make lint
```

Cross-build (CGO disabled by default):

```bash
make cross-build
```

Targets produced in dist:

- tgap-darwin-amd64
- tgap-darwin-arm64
- tgap-linux-amd64
- tgap-linux-arm64
- tgap-windows-amd64.exe

Note: local `make build` also creates `dist/tracegap` as a symlink to `dist/tgap`.

## Developer Quick Start

Build a local binary:

```bash
make build
```

You can also run directly with Go:

```bash
go run ./cmd/tgap audit path/to/trace.json
```

Supported commands only:

```bash
tgap audit trace.json
tgap audit trace.json --format json
tgap audit trace.json --repo .
tgap --version
tgap --help
tracegap audit trace.json
tracegap audit trace.json --format json
tracegap audit trace.json --repo .
tracegap --version
tracegap --help
```

No other commands are implemented.

## Notes

- Analysis is based on direct children of each root span in v1.
- Guidance is intentionally probabilistic and pattern-based.
- Repo-aware analysis runs only when --repo is provided.
