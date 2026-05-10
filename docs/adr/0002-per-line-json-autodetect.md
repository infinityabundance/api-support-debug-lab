# ADR-0002: Per-line JSON-or-text log auto-detection

- **Status**: Accepted
- **Date**: 2026-05-10

## Context

`server.log` files in the bundled fixtures use two formats:
plain-text key=value lines (`auth_missing/server.log`) and
JSON-lines (`timeout_retry_jsonl/server.log`). Real production
logs are split between these styles, and a single tool that
classifies one customer's logs might see both within a single
incident.

Three options for handling this:

1. Force one format. Reject the others.
2. Switch on file extension (`.log` vs `.jsonl`).
3. Auto-detect per line.

## Decision

Per-line auto-detection. `LogLine::parse` in `src/rules.rs` runs
`serde_json::from_str` if the line begins with `{`; otherwise it
treats the line as whitespace-separated `key=value` text. Both
paths converge on a uniform query API (`field`, `contains_ci`).

## Consequences

**Positive.**

- The same fixture directory layout works for both formats — no
  filename convention to remember.
- A real production log that *mixes* formats (e.g., a structured
  request line and an unstructured stack trace on the next line)
  is parseable without preprocessing.
- The rule layer above is format-agnostic; rules use `field("key")`
  and `contains_ci("needle")` without branching.

**Negative.**

- One `serde_json::from_str` call per JSON line, even if the line
  contains no fields the rule needs. For the bundled fixtures
  (≤ 8 lines per log) the cost is negligible (~150 ns per line);
  at production scale (10⁵+ lines) a streaming parser would be
  more appropriate.
- The autodetect heuristic ("starts with `{`") is naive. A
  pathological log line that begins with `{` but is actually
  whitespace-delimited text would fall through `serde_json::from_str`
  with `None` and then through to the text path, costing extra work
  but producing the right answer.

**Neutral.**

- A future revision could promote `LogLine` from a private rule
  helper to a public type if external callers want to reuse the
  parser. Out of scope for v0.x.
