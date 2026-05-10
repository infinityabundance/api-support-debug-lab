# API Support Debug Lab

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/infinityabundance/api-support-debug-lab/blob/main/colab/api_debug_lab.ipynb)

A reproducible developer-support debugging lab. The repository contains
intentionally-failing API request fixtures (request, response, server log)
and a Rust diagnostic CLI that classifies the failure, recomputes the
relevant evidence, and emits next steps and a draft escalation note.

The artefact answers a single question: *given the same fixtures a real
support engineer might receive, how does the candidate reproduce, classify,
and communicate?*

## At a glance

```text
$ api-debug-lab list-cases | wc -l        # bundled positive fixtures
14
$ cargo test --tests 2>&1 | grep "test result: ok" | wc -l
9                                          # nine independent test groups, all green
$ cargo llvm-cov --summary-only | tail -1
TOTAL  ...  92.38 % regions covered
$ cargo mutants --in-place --file src/rules.rs --no-shuffle | tail -1
183 mutants tested in 3m: 15 missed, 154 caught, 14 unviable   # 91 % kill rate
```

Eight rules, fourteen bundled positive fixtures, eleven bundled negative
fixtures, three real-API webhook envelopes (Stripe v1, Slack v0,
GitHub HMAC), a 36-case Brier-calibrated confidence corpus with a
regression canary, oracle HMAC tests pinned to externally-computed
reference vectors, single-digit-microsecond per-case latency,
93 % line coverage, 91 % mutation kill rate, ~90 tests across nine
groups, three ADRs documenting the design choices.

## Money shot

```text
$ api-debug-lab diagnose auth_missing
CASE: auth_missing
SEVERITY: medium
LIKELY CAUSE: Missing Authorization header
CONFIDENCE: 0.95
RULE: auth_missing

EVIDENCE:
- Authorization header absent in request
- Endpoint POST https://api.acme-co.example/v1/events flagged auth_required=true
- Response status 401 Unauthorized

REPRODUCTION:
curl -X POST https://api.acme-co.example/v1/events \
  -H "content-type: application/json" \
  -H "user-agent: acme-client/0.4.1" \
  --data-raw '{"event":"order.created","order_id":"ord_8KZ"}'

NEXT STEPS:
1. Add an Authorization: Bearer <token> header to the request.
2. Confirm the token has not expired.
3. Verify the token's scope covers the requested operation.

ESCALATION NOTE:
Customer request failed because the Authorization header was absent.
The API rejected the request before payload processing. Ask the customer
to retry with a valid bearer token and confirm the token's scope.
```

## Arbitration in action

When more than one rule fires, the highest-confidence diagnosis is
reported as `primary` and the rest as `also_considered`. Tie-breaks are
alphabetical on `rule_id` so output is byte-stable.

```text
$ api-debug-lab diagnose webhook_signature_invalid_stale
LIKELY CAUSE: Webhook signature does not match recomputed HMAC
CONFIDENCE: 0.92
RULE: webhook_signature_mismatch
...
ALSO CONSIDERED:
- webhook_timestamp_stale (confidence 0.90): Webhook timestamp outside tolerance window
```

HMAC mismatch is rated higher than timestamp drift because a wrong digest
is dispositive (secret, body, or timestamp prefix differs) while clock
skew has benign causes. The confidence rubric is documented in
[docs/confidence_model.md](docs/confidence_model.md).

## What this demonstrates

- API troubleshooting against fixtures that look like real support tickets.
- Log + header inspection with structural checks (HMAC recompute, JSON
  parse, rate-limit header math, hostname Hamming distance, idempotency
  body-hash comparison) — not just status-code grep.
- Confidence-ranked arbitration when multiple rules fire, with a
  documented confidence model and a Brier-score calibration test.
- Production realism: Stripe-style multi-version webhook envelopes,
  JSON-lines log auto-detection, RFC3339 timestamp derivation, partial-
  outage interleaved request streams.
- A Rust CLI with `clap` derive, snapshot tests via `insta`,
  property-based tests via `proptest`, end-to-end CLI tests via
  `assert_cmd`, and `criterion` benchmarks.
- Honest scope: rule-based, eight failure modes, no machine learning,
  no network calls, no telemetry.

## Quick start

```bash
cargo install api-debug-lab
api-debug-lab list-cases
api-debug-lab diagnose auth_missing
api-debug-lab diagnose webhook_signature_invalid_stale --format json | jq
```

Requires a stable Rust toolchain (1.78+). No service to start, no Docker.
The bundled fixtures are embedded in the installed binary; pass
`--fixtures <dir>` to diagnose a local fixture directory instead.

From a source checkout:

```bash
cargo run -- list-cases
cargo run -- diagnose auth_missing
cargo run -- corpus fixtures/cases | tail -25
cargo test
```

## Failure cases

| Case                              | Structural signal beyond status code                                       |
| --------------------------------- | -------------------------------------------------------------------------- |
| `auth_missing`                    | `Authorization` header literally absent on an `auth_required` route        |
| `bad_json_payload`                | `serde_json` parser error and byte offset on the request body              |
| `rate_limited`                    | `Retry-After`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` parsed         |
| `webhook_signature_invalid`       | HMAC-SHA256 recomputed over `"{ts}.{body}"` and compared                   |
| `webhook_signature_invalid_stale` | Ambiguous: signature mismatch *and* timestamp drift; both rules fire       |
| `webhook_stripe_v1`               | Stripe envelope `t=,v1=,v0=` parsed; multi-version HMAC compare            |
| `webhook_slack_v0`                | Slack envelope `v0=`; HMAC over `"v0:{ts}:{body}"`                         |
| `webhook_github_hmac`             | GitHub `sha256=`; HMAC over the raw body (no timestamp)                    |
| `timeout_retry`                   | Log lines grouped by request id; elapsed derived from RFC3339 stamps       |
| `timeout_retry_jsonl`             | Same shape but server log is JSON-lines (per-line auto-detect)             |
| `timeout_retry_partial_outage`    | Two request_ids interleaved; rule isolates the worst offender              |
| `timeout_retry_midnight_rollover` | Log spans midnight UTC; elapsed derived correctly across day boundary      |
| `config_dns_error`                | URL host parsed; near-miss (Hamming-distance) and TLD checks               |
| `idempotency_collision`           | Recomputed body SHA-256 compared against the stored hash                   |

Negatives that look similar but should *not* classify live under
[fixtures/cases/_negatives/](fixtures/cases/_negatives/) — one per rule,
including a `webhook_clean` with a valid HMAC, a `webhook_stripe_v1_clean`
with a valid Stripe v1 envelope, a 401 from an unrelated upstream call,
and an idempotency-clean retry with byte-identical body.

## CLI

```text
api-debug-lab list-cases                          # bundled fixtures
api-debug-lab diagnose <name|path>                # human report
api-debug-lab diagnose <name> --format json       # machine-readable
api-debug-lab diagnose <name> --trace             # per-rule timing on stderr
api-debug-lab explain  <name>                     # rule + evidence pointers
api-debug-lab replay   <name>                     # curl repro + diagnosis
api-debug-lab report   <name>                     # alias for human diagnose
api-debug-lab corpus   <dir>                      # sweep an arbitrary dir
api-debug-lab corpus   <dir> --ndjson             # one JSON object per line
```

Exit codes: `0` diagnosed (confidence ≥ 0.60), `1` unclassified or
low-confidence, `2` bad input.

## Architecture

```
fixtures/cases/<name>/case.json       →  Case (serde, schema-validated)  ┐
fixtures/cases/<name>/server.log      →  &str (lazy load, JSONL or text) ├→ Rule[] → Diagnosis[] → Report
fixtures/cases/<name>/secret.txt      →  Vec<u8>                         ┘   (sorted by
                                                                              confidence desc)
```

- [src/cases.rs](src/cases.rs)     — `Case`, loader, schema-validated by [fixtures/cases.schema.json](fixtures/cases.schema.json) (JSON Schema Draft 2020-12).
- [src/rules.rs](src/rules.rs)     — `Rule` trait, eight rule impls, `diagnose`, `diagnose_traced`, per-line `LogLine` JSONL/text autodetect, RFC3339 timestamp derivation.
- [src/evidence.rs](src/evidence.rs)  — `Evidence` + `Pointer` (source + optional log line).
- [src/report.rs](src/report.rs)    — human / JSON formatters; deterministic curl reproduction.
- [src/main.rs](src/main.rs)      — `clap` subcommands, exit codes, `--trace`, `corpus` sweep.

All output is byte-stable across machines: header iteration uses
`BTreeMap`, reproductions inline the body (no absolute paths), no
system clock or RNG.

## Tests and benchmarks

```bash
cargo test --all-targets               # ~70 tests
cargo bench --bench diagnose -- --quick # microsecond per-case latency
cargo deny check                        # supply-chain (CI)
cargo audit                             # advisories  (CI)
```

Test coverage:

- **Per-rule unit tests** ([tests/rules.rs](tests/rules.rs)) — positive +
  paired negative for each rule.
- **Snapshot tests** ([tests/snapshots.rs](tests/snapshots.rs)) — human
  and JSON renders of every fixture, pinned via `insta`.
- **Property-based tests** ([tests/properties.rs](tests/properties.rs))
  — proptest invariants: no rule panics on any schema-valid case;
  diagnose is idempotent; confidence is finite and in [0, 1];
  `also_considered` is sorted descending and below the primary;
  hand-written adversarial fixtures (1 MiB body, NUL byte, far-future
  timestamp, extreme URL).
- **Schema validation** ([tests/schema.rs](tests/schema.rs)) — every
  bundled `case.json` validates against
  [fixtures/cases.schema.json](fixtures/cases.schema.json).
- **CLI integration** ([tests/diagnose_cli.rs](tests/diagnose_cli.rs))
  — `assert_cmd` end-to-end for each subcommand, including a tempdir
  test for `corpus` over a copied fixture.
- **Confidence calibration** ([tests/calibration.rs](tests/calibration.rs))
  — five distinct properties over the labelled corpus
  (`expected_rule_id` labels embedded in each enrolled `case.json`,
  36 cases × 8 rules = 288 (case, rule) pairs):
  aggregate Brier ≤ 0.05, per-rule Brier ≤ 0.08, ECE ≤ 0.05,
  100 % primary-classification accuracy, unclassified cases below
  threshold. Rubric in
  [docs/confidence_model.md](docs/confidence_model.md).
- **Calibration regression canary**
  ([tests/calibration_regression.rs](tests/calibration_regression.rs))
  — a feature-gated test (`--features calibration_canary`) that
  simulates a deliberately-miscalibrated rule and asserts the
  production Brier check would have caught it. Runs in a separate
  CI job. Proves the calibration framework is load-bearing rather
  than ceremonial.
- **Oracle / differential HMAC tests**
  ([tests/oracle.rs](tests/oracle.rs)) — three reference signatures
  hand-computed via `openssl` and pinned in source. Catches future
  signing-input drift that self-consistent round-trip tests would
  miss.
- **Latency-budget regression test**
  ([tests/latency_budget.rs](tests/latency_budget.rs)) — asserts
  per-rule median wall-clock evaluation is below 100 µs across 200
  iterations per fixture.
- **Mutation testing report**
  ([docs/mutation_report.md](docs/mutation_report.md)) — 91 % kill
  rate over 169 viable mutants in `src/rules.rs`, surviving mutants
  classified (gap / benign / equivalent).
- **Code coverage snapshot**
  ([docs/coverage.md](docs/coverage.md)) — 92.4 % regions, 91.7 %
  functions, 93.0 % lines via `cargo-llvm-cov`, date- and
  rustc-version-stamped.

Snapshot updates after intentional output changes:

```bash
cargo install cargo-insta
cargo insta review
```

Benchmarks run in `--quick` mode under a second; full mode under ten
seconds. Baseline numbers and methodology in
[docs/benchmarks.md](docs/benchmarks.md).

## Limitations and scope

This is a demo / portfolio artefact. Honest limits:

- **Rule-based, not learned.** Eight hand-written rules; no ML, no model.
  The confidence rubric is documented in
  [docs/confidence_model.md](docs/confidence_model.md) and held
  accountable by aggregate Brier, per-rule Brier, ECE, and a
  feature-gated regression canary in `tests/calibration*.rs`.
- **Eight failure modes.** Real support traffic has many more; the rule
  set is illustrative.
- **Synthetic fixtures.** Modelled on the *shape* of production logs
  and the documented envelope formats of Stripe v1, Slack v0, and
  GitHub HMAC, but invented; no real customer data.
- **No network.** Reproductions print `curl` for the reviewer to run by
  hand; the binary itself never opens a socket.
- **No background service.** The lab is the binary plus the fixtures.

## License

Apache-2.0. See [LICENSE](LICENSE).
