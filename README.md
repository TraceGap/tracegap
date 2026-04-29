# TraceGap

TraceGap is a local CLI for auditing tracing coverage in a single trace file.

It answers one question:

How much parent request time is not covered by direct child spans?

The v1 wedge is intentionally narrow and sharp:

- No backend
- No network calls
- No auth
- No config files

## Install

Build a local binary:

```bash
make build
```

Binary output:

```text
dist/tgap
```

You can also run directly with Go:

```bash
go run ./cmd/tgap audit path/to/trace.json
```

## Command Surface (v1)

Supported commands only:

```bash
tgap audit trace.json
tgap audit trace.json --format json
```

No other commands are implemented in v1.

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

## Text Output Example

```text
TraceGap Audit
Schema: OTLP

Root span: checkout.request (1s)
⚠️ A significant portion of this request is not traced (50% missing)

Trace coverage: 50%
Unaccounted time: 50% (500ms)

Largest gaps:
1. 700ms-1s (300ms) after inventory
2. 200ms-400ms (200ms) between auth and inventory
Recommended checks:
- Add spans around external calls (HTTP, DB, RPC)
- Ensure trace context propagation (headers/context)
- Inspect retry/backoff or async logic
- Check framework/middleware instrumentation

checkout.request (1s)
================................========================........................
covered: 500ms | gap: 500ms

Find where this missing time comes from:
https://tracegap.io
```

Timeline symbols:

- Unicode mode: covered = █, gap = ·
- ASCII fallback: covered = =, gap = .

Force ASCII mode:

```bash
TGAP_ASCII=1 tgap audit trace.json
```

## JSON Output Example

```bash
tgap audit trace.json --format json
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

To get started:
   Export a trace as JSON (OTLP/Jaeger) and run:
   tgap audit <trace.json>
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

## Notes

- Analysis is based on direct children of each root span in v1.
- Guidance is intentionally probabilistic and pattern-based.
- TraceGap does not inspect source code in v1.
