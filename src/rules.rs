// SPDX-License-Identifier: Apache-2.0

//! The rule layer.
//!
//! Eight rules cover seven failure modes; the webhook case is split
//! into a signature-mismatch rule and a timestamp-staleness rule so
//! they can fire independently and arbitration ranks them by
//! confidence. Public surface:
//!
//! - The [`Rule`] trait. One implementation per failure mode.
//! - [`all_rules`] — returns the registered rules in evaluation order.
//! - [`diagnose`] — runs every rule, sorts by descending confidence,
//!   returns a [`Report`].
//! - [`diagnose_traced`] — same as [`diagnose`] but also returns a
//!   [`RuleTrace`] per rule (wall-clock timing + outcome). Used by
//!   the CLI's `--trace` flag and by `benches/diagnose.rs`.
//!
//! ## Adding a rule
//!
//! 1. Add a private struct that implements [`Rule`].
//! 2. Register it in [`all_rules`].
//! 3. Add a positive fixture (`fixtures/cases/<name>/case.json`) and
//!    a paired negative under `_negatives/` that looks similar but
//!    must not classify.
//! 4. Add an `expected_rule_id` label to every calibration fixture
//!    that should exercise the rule.
//! 5. Document the rule's confidence rubric in
//!    `docs/confidence_model.md`.
//! 6. Run `cargo test` and `cargo insta review` to accept the new
//!    snapshots.
//!
//! ## Confidence model
//!
//! Confidence values are not arbitrary; the rubric in
//! `docs/confidence_model.md` lays out the bands (dispositive,
//! strong, moderate, inadmissible) and `tests/calibration.rs`
//! enforces them via Brier score over the labelled corpus.

use std::collections::BTreeMap;

use crate::cases::{header, Case, EnvelopeFormat};
use crate::evidence::Evidence;
use crate::report::{self, Diagnosis, Report};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use url::Url;

/// A single log line, parsed lazily as JSON if it begins with `{`,
/// otherwise treated as whitespace-separated `key=value` text.
///
/// Both formats expose the same query API ([`LogLine::field`],
/// [`LogLine::contains_ci`]) so the rules above this layer do not
/// branch on log shape. The JSON path is taken only when the line
/// starts with `{`; for text logs no `serde_json` work happens.
///
/// The struct borrows the original line; the optional JSON value is
/// the one allocation incurred per JSONL line. For the small fixtures
/// in this lab (≤ 8 lines per log) the cost is negligible.
struct LogLine<'a> {
    /// The raw input line (borrowed from the loaded log string).
    raw: &'a str,
    /// `Some(parsed)` when the line was valid JSON; `None` when the
    /// line was treated as text.
    json: Option<serde_json::Value>,
}

impl<'a> LogLine<'a> {
    /// Construct a `LogLine` from a raw line. The leading `{`
    /// triggers a single `serde_json` parse attempt; if it fails or
    /// the line does not start with `{`, the line is treated as
    /// text. Both paths converge on the same query API below.
    fn parse(raw: &'a str) -> Self {
        let json = if raw.trim_start().starts_with('{') {
            serde_json::from_str(raw).ok()
        } else {
            None
        };
        Self { raw, json }
    }

    /// Return the original (un-parsed) line bytes. Useful for
    /// echoing into evidence verbatim and for timestamp parsing
    /// (RFC3339 is the same shape in both formats).
    fn raw(&self) -> &'a str {
        self.raw
    }

    /// Read a field value. JSON path takes precedence; fallback is
    /// whitespace-separated `key=value` text. Returns the value as
    /// an owned string so callers do not have to track the borrow
    /// across format branches.
    fn field(&self, key: &str) -> Option<String> {
        if let Some(v) = self.json.as_ref().and_then(|j| j.get(key)) {
            return Some(match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => v.to_string(),
            });
        }
        let prefix = format!("{key}=");
        self.raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix(&prefix))
            .map(|s| s.trim_matches('"').to_string())
    }

    /// Case-insensitive substring match.
    ///
    /// For JSON lines this matches against any string value or any
    /// key in the top-level object — the value form catches
    /// `status:"upstream_timeout"` and the key form catches the
    /// presence of an `error_message` key. For text lines it falls
    /// back to a lowercased substring check on the raw bytes.
    ///
    /// `needle_lc` must already be lower-case; the caller is
    /// responsible for that.
    fn contains_ci(&self, needle_lc: &str) -> bool {
        if let Some(v) = &self.json {
            if let Some(obj) = v.as_object() {
                for value in obj.values() {
                    if let Some(s) = value.as_str() {
                        if s.to_ascii_lowercase().contains(needle_lc) {
                            return true;
                        }
                    }
                }
            }
            if let Some(obj) = v.as_object() {
                for key in obj.keys() {
                    if key.to_ascii_lowercase().contains(needle_lc) {
                        return true;
                    }
                }
            }
            return false;
        }
        self.raw.to_ascii_lowercase().contains(needle_lc)
    }
}

/// Parse the leading RFC3339-ish timestamp (`YYYY-MM-DDTHH:MM:SS.sssZ`)
/// out of a log line and return milliseconds since the Unix epoch
/// (1970-01-01T00:00:00Z).
///
/// This is *not* a full RFC3339 parser; it does not handle timezone
/// offsets other than `Z` and does not handle leap seconds. It does
/// handle dates in proleptic Gregorian calendar via Howard Hinnant's
/// `days_from_civil` algorithm, so timestamps that span midnight UTC
/// produce the right elapsed difference. Returns `None` if the line
/// does not start with a recognisable timestamp.
///
/// The returned value is `i64` (signed) so timestamps before 1970
/// remain representable; the `timeout_retry` rule converts to `u64`
/// after subtracting one timestamp from another.
fn parse_timestamp_ms(line: &str) -> Option<i64> {
    let t_idx = line.find('T')?;
    let date_str = &line[..t_idx];
    let after_t = line.get(t_idx + 1..)?;
    let z_idx = after_t.find('Z')?;
    let time_str = &after_t[..z_idx];

    // Parse "YYYY-MM-DD"
    let mut date_iter = date_str.split('-');
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: u32 = date_iter.next()?.parse().ok()?;
    let day: u32 = date_iter.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Parse "HH:MM:SS[.frac]"
    let mut iter = time_str.split(':');
    let h: i64 = iter.next()?.parse().ok()?;
    let m: i64 = iter.next()?.parse().ok()?;
    let s_part = iter.next()?;
    let (sec_str, frac_str) = match s_part.split_once('.') {
        Some((s, f)) => (s, f),
        None => (s_part, "0"),
    };
    let s: i64 = sec_str.parse().ok()?;
    let mut frac_padded = frac_str.to_string();
    while frac_padded.len() < 3 {
        frac_padded.push('0');
    }
    let millis: i64 = frac_padded.get(..3)?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let ms_of_day = ((h * 60 + m) * 60 + s) * 1000 + millis;
    Some(days * 86_400_000 + ms_of_day)
}

/// Days since the Unix epoch (1970-01-01) for a proleptic Gregorian
/// date. Howard Hinnant's `days_from_civil` algorithm — exact, no
/// table lookups, handles dates from year ±5,879,000 without
/// overflow.
///
/// See: <http://howardhinnant.github.io/date_algorithms.html>
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u32; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // March-based [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// Parsed view of a webhook's signature-bearing header for the
/// envelope formats this lab supports.
struct WebhookEnvelope {
    /// Unix timestamp claimed by the envelope (or read from the
    /// configured timestamp header for the `raw` format).
    timestamp: Option<i64>,
    /// Candidate signatures to compare the recomputed HMAC against.
    /// For `raw` this has one element; for `stripe_v1` it can have
    /// `v1=` and `v0=` entries.
    signatures: Vec<String>,
    /// Best human label for the provided signature, used in evidence.
    label: String,
}

/// Parse the signature-bearing header into the canonical
/// [`WebhookEnvelope`] shape used by both webhook rules.
///
/// For [`EnvelopeFormat::Raw`]: the header value is a single hex
/// digest (optionally `sha256=`-prefixed); the timestamp comes from
/// `ts_header_value` (which is read from a separate header).
///
/// For [`EnvelopeFormat::StripeV1`]: the header is parsed as
/// `t=<unix_ts>,v1=<sig>,v0=<sig>,...`. Multiple `v1`/`v0`
/// entries are all collected so that key rotation (multiple active
/// secrets, both signed) can pass if any matches.
fn parse_envelope(
    format: EnvelopeFormat,
    sig_header_value: &str,
    ts_header_value: &str,
) -> WebhookEnvelope {
    match format {
        EnvelopeFormat::Raw => {
            let normalised = sig_header_value
                .trim()
                .trim_start_matches("sha256=")
                .to_string();
            let timestamp: Option<i64> = ts_header_value.trim().parse().ok();
            WebhookEnvelope {
                timestamp,
                signatures: vec![normalised],
                label: sig_header_value.to_string(),
            }
        }
        EnvelopeFormat::StripeV1 => {
            let mut timestamp: Option<i64> = None;
            let mut signatures: Vec<String> = Vec::new();
            for part in sig_header_value.split(',') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    match k {
                        "t" => timestamp = v.trim().parse().ok(),
                        "v1" | "v0" => signatures.push(v.trim().to_string()),
                        _ => {}
                    }
                }
            }
            WebhookEnvelope {
                timestamp,
                signatures,
                label: sig_header_value.to_string(),
            }
        }
        EnvelopeFormat::SlackV0 => {
            // Slack header value: "v0=<hex>" (single signature).
            let normalised = sig_header_value
                .trim()
                .trim_start_matches("v0=")
                .to_string();
            let timestamp: Option<i64> = ts_header_value.trim().parse().ok();
            WebhookEnvelope {
                timestamp,
                signatures: vec![normalised],
                label: sig_header_value.to_string(),
            }
        }
        EnvelopeFormat::GithubHmac => {
            // GitHub does not send a timestamp; `ts_header_value` is
            // ignored, and `webhook_timestamp_stale` cannot fire on
            // this envelope by construction.
            let normalised = sig_header_value
                .trim()
                .trim_start_matches("sha256=")
                .to_string();
            WebhookEnvelope {
                timestamp: None,
                signatures: vec![normalised],
                label: sig_header_value.to_string(),
            }
        }
    }
}

/// One diagnostic rule.
///
/// A rule looks at a [`Case`] and either fires (returns a
/// [`Diagnosis`]) or stays silent (returns `None`). Rules are pure:
/// they do not mutate the case, do not read environment variables,
/// and do not perform network I/O. Local file reads (logs, secrets)
/// go through [`Case::load_log`] and [`Case::load_secret`].
///
/// `Send + Sync` is required so that the registered rules can sit
/// behind a `Box<dyn Rule>` and be safely shared across threads if
/// a future caller wants to parallelise the sweep — the current
/// orchestrator runs them sequentially because the per-case latency
/// is single-digit microseconds.
pub trait Rule: Send + Sync {
    /// Stable identifier used in reports, logs, snapshot tests, and
    /// the calibration corpus. Must be unique within [`all_rules`]
    /// and match the corresponding fixture's `expected_rule_id`.
    fn id(&self) -> &str;

    /// Evaluate this rule against the case. Return `Some(diagnosis)`
    /// to fire, `None` to stay silent.
    ///
    /// Implementations should return early with `None` whenever a
    /// required signal is absent (no auth context, no webhook
    /// secret, no log file, etc.). The orchestrator does not penalise
    /// silent rules; only firing rules contribute to the report.
    fn evaluate(&self, case: &Case) -> Option<Diagnosis>;
}

/// The eight bundled rules, stored as a `'static` slice over
/// zero-sized rule structs. `all_rules()` returns this slice
/// directly — no heap allocation per call.
///
/// Order is not significant for correctness — the orchestrator sorts
/// by confidence — but it does control trace output and tie-breaking
/// when confidences are equal. The current order roughly matches
/// request-lifecycle phase (auth → payload parse → rate limit →
/// webhook verify → upstream timeout → config → idempotency).
static RULES: &[&dyn Rule] = &[
    &AuthMissing,
    &BadJsonPayload,
    &RateLimited,
    &WebhookSignatureMismatch,
    &WebhookTimestampStale,
    &TimeoutRetry,
    &ConfigDnsError,
    &IdempotencyCollision,
];

/// Return the registered rules in evaluation order.
///
/// Rules are zero-sized structs, so the returned slice is a pointer
/// into static memory and `all_rules()` is essentially free.
pub fn all_rules() -> &'static [&'static dyn Rule] {
    RULES
}

/// Per-rule trace entry produced by [`diagnose_traced`].
#[derive(Debug, Clone)]
pub struct RuleTrace {
    /// Stable identifier of the rule (matches `Rule::id`).
    pub rule_id: String,
    /// Wall-clock duration of `Rule::evaluate` for this case.
    pub duration: std::time::Duration,
    /// Confidence emitted, or `None` if the rule did not fire.
    pub confidence: Option<f32>,
}

/// Run every rule, sort firing diagnoses by descending confidence, and return
/// a [`Report`] with the top hit as `primary` and the rest in `also_considered`.
///
/// Tie-breaking is alphabetical on `rule_id` so output is byte-stable.
///
/// # Examples
///
/// ```no_run
/// use api_debug_lab::{diagnose, Case};
/// use std::path::Path;
///
/// let case = Case::load("auth_missing", Path::new("fixtures"))?;
/// let report = diagnose(&case);
/// assert_eq!(report.primary.unwrap().rule_id, "auth_missing");
/// # Ok::<(), api_debug_lab::CaseLoadError>(())
/// ```
pub fn diagnose(case: &Case) -> Report {
    let (report, _trace) = diagnose_traced(case);
    report
}

/// Same as [`diagnose`] but also returns a per-rule trace recording each
/// rule's wall-clock evaluation time and whether it fired.
///
/// Useful for `--trace` output and for benchmarking. Trace entries are
/// returned in the order rules ran (the order from [`all_rules`]), not
/// the order they appear in the report.
///
/// # Examples
///
/// ```no_run
/// use api_debug_lab::{diagnose_traced, Case};
/// use std::path::Path;
///
/// let case = Case::load("auth_missing", Path::new("fixtures"))?;
/// let (report, traces) = diagnose_traced(&case);
/// assert_eq!(traces.len(), 8); // one trace per rule
/// assert!(report.primary.is_some());
/// # Ok::<(), api_debug_lab::CaseLoadError>(())
/// ```
pub fn diagnose_traced(case: &Case) -> (Report, Vec<RuleTrace>) {
    let rules = all_rules();
    let mut hits: Vec<Diagnosis> = Vec::with_capacity(rules.len());
    let mut traces: Vec<RuleTrace> = Vec::with_capacity(rules.len());
    for rule in rules {
        let start = std::time::Instant::now();
        let outcome = rule.evaluate(case);
        let duration = start.elapsed();
        let confidence = outcome.as_ref().map(|d| d.confidence);
        traces.push(RuleTrace {
            rule_id: rule.id().to_string(),
            duration,
            confidence,
        });
        if let Some(d) = outcome {
            hits.push(d);
        }
    }
    hits.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    let mut iter = hits.into_iter();
    let primary = iter.next();
    let also_considered: Vec<Diagnosis> = iter.collect();
    let report = Report {
        case_name: case.name.clone(),
        severity: case.severity,
        primary,
        also_considered,
        reproduction: report::reproduction(case),
    };
    (report, traces)
}

// ---------------------------------------------------------------------------
// Rule 1 — auth_missing
//
// Fires when an `auth_required` route received a request with no
// `Authorization` header. Confidence is 0.95 when the response also
// returned 401 (three independent signals agree); 0.60 when the
// request was captured before any response (signals 1 + 2 only).
// ---------------------------------------------------------------------------

struct AuthMissing;

impl Rule for AuthMissing {
    fn id(&self) -> &str {
        "auth_missing"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        // Required-precondition gates first: no need to inspect a route
        // that does not require auth or that already carries a token.
        if !case.context.auth_required {
            return None;
        }
        if header(&case.request.headers, "authorization").is_some() {
            return None;
        }
        let status = case.response.as_ref().map(|r| r.status).unwrap_or(0);
        let mut evidence = vec![
            Evidence::with(
                "Authorization header absent in request",
                "request.headers.authorization",
            ),
            Evidence::with(
                format!(
                    "Endpoint {} {} flagged auth_required=true",
                    case.request.method, case.request.url
                ),
                "case.context.auth_required",
            ),
        ];
        let confidence = if status == 401 {
            evidence.push(Evidence::with(
                "Response status 401 Unauthorized",
                "response.status",
            ));
            0.95
        } else {
            0.60
        };
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Missing Authorization header".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Add an Authorization: Bearer <token> header to the request.".into(),
                "Confirm the token has not expired.".into(),
                "Verify the token's scope covers the requested operation.".into(),
            ],
            escalation: "Customer request failed because the Authorization header was \
                         absent. The API rejected the request before payload processing. \
                         Ask the customer to retry with a valid bearer token and confirm \
                         the token's scope."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 2 — bad_json_payload
//
// Actually parses the request body with `serde_json` and reports the
// real parse error and byte offset, rather than guessing from the
// status code. The negative fixture `valid_json_schema_fail` proves
// this rule does not fire when the body parses but fails downstream
// schema validation — a different remediation entirely.
// ---------------------------------------------------------------------------

struct BadJsonPayload;

impl Rule for BadJsonPayload {
    fn id(&self) -> &str {
        "bad_json_payload"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        // Need a body and a JSON content type — without these the rule
        // has no input to parse.
        let body = case.request.body.as_deref()?;
        let ct = header(&case.request.headers, "content-type").unwrap_or("");
        if !ct.contains("application/json") {
            return None;
        }
        // Record the actual parser error including byte offset so the
        // evidence is provably about the bytes the customer sent, not
        // a heuristic about status codes.
        let parse_err = match serde_json::from_str::<serde_json::Value>(body) {
            Ok(_) => return None,
            Err(e) => e,
        };
        let status = case.response.as_ref().map(|r| r.status).unwrap_or(0);
        let mut evidence = vec![
            Evidence::with(
                format!(
                    "serde_json parse error at line {} column {}: {}",
                    parse_err.line(),
                    parse_err.column(),
                    parse_err
                ),
                "request.body",
            ),
            Evidence::with(
                format!("Content-Type was {ct}; body could not be parsed"),
                "request.headers.content-type",
            ),
        ];
        let confidence = if matches!(status, 400 | 422) {
            evidence.push(Evidence::with(
                format!("Response status {status} confirms server rejected payload"),
                "response.status",
            ));
            0.95
        } else {
            0.70
        };
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Invalid JSON payload".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Validate the payload against the documented request schema.".into(),
                "Re-emit the body using a JSON serialiser (avoid hand-built strings).".into(),
                "If the issue persists, log the raw request bytes before send.".into(),
            ],
            escalation: "The request body could not be parsed as JSON. The server \
                         rejected the request before any business logic ran. Ask the \
                         customer to share the exact bytes they sent and the producer \
                         that built them."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 3 — rate_limited
//
// 429 alone is not enough to be useful in a ticket — the customer
// already knows. The rule's job is to extract the rate-limit math
// from headers (`Retry-After`, `X-RateLimit-Remaining`,
// `X-RateLimit-Reset`) so the next-step guidance is a number, not
// a vibe.
// ---------------------------------------------------------------------------

struct RateLimited;

impl Rule for RateLimited {
    fn id(&self) -> &str {
        "rate_limited"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let resp = case.response.as_ref()?;
        // The negative fixture `non_429_high_traffic` carries
        // rate-limit headers on a 200 response; this gate is what
        // keeps the rule from over-firing on those.
        if resp.status != 429 {
            return None;
        }
        let mut evidence = vec![Evidence::with(
            "Response status 429 Too Many Requests",
            "response.status",
        )];
        let mut confidence: f32 = 0.70;
        if let Some(remaining) = header(&resp.headers, "x-ratelimit-remaining") {
            evidence.push(Evidence::with(
                format!("X-RateLimit-Remaining: {remaining}"),
                "response.headers.x-ratelimit-remaining",
            ));
            if remaining.trim() == "0" {
                confidence = confidence.max(0.95);
            } else {
                confidence = confidence.max(0.85);
            }
        }
        if let Some(retry_after) = header(&resp.headers, "retry-after") {
            evidence.push(Evidence::with(
                format!("Retry-After: {retry_after} seconds"),
                "response.headers.retry-after",
            ));
            confidence = confidence.max(0.95);
        }
        if let Some(reset) = header(&resp.headers, "x-ratelimit-reset") {
            evidence.push(Evidence::with(
                format!("X-RateLimit-Reset (epoch): {reset}"),
                "response.headers.x-ratelimit-reset",
            ));
        }
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Rate limit exceeded".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Honour the Retry-After header before resending.".into(),
                "Implement client-side exponential backoff with jitter.".into(),
                "Reduce request frequency or request a higher quota.".into(),
            ],
            escalation: "Customer is hitting the documented rate limit. Confirm whether \
                         the spike is intentional (campaign / migration) or a runaway \
                         loop, and whether a temporary quota bump is appropriate."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 4 — webhook_signature_mismatch
//
// The dispositive rule of the lab. It actually recomputes the HMAC
// over `"{timestamp}.{body}"` using the bundled secret and compares
// against the provided signature(s). For Stripe v1 envelopes both
// `v1=` and `v0=` candidates are checked — a single match counts as
// pass. Confidence is a flat 0.92: HMAC mismatch is mathematical
// proof of *some* divergence (secret, body, or timestamp prefix);
// there is no weaker form of "the digests don't match".
// ---------------------------------------------------------------------------

struct WebhookSignatureMismatch;

impl Rule for WebhookSignatureMismatch {
    fn id(&self) -> &str {
        "webhook_signature_mismatch"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let webhook = case.context.webhook.as_ref()?;
        let secret = case.load_secret()?;
        let provided_raw = header(&case.request.headers, &webhook.signature_header)?;
        let ts_raw = header(&case.request.headers, &webhook.timestamp_header).unwrap_or("");
        // `parse_envelope` returns one signature for raw envelopes and
        // potentially several for stripe_v1 (v1, v0, ...). All are
        // treated as pass-if-any-matches.
        let env = parse_envelope(webhook.envelope_format, provided_raw, ts_raw);
        if env.signatures.is_empty() {
            return None;
        }
        // The signing-input shape is per-envelope. Each variant maps
        // to the documented scheme of a real-world API (see
        // `EnvelopeFormat` in `src/cases.rs`).
        let timestamp = env.timestamp.map(|t| t.to_string()).unwrap_or_default();
        let body = case.request.body.as_deref().unwrap_or("");
        let signing_input = match webhook.envelope_format {
            EnvelopeFormat::Raw | EnvelopeFormat::StripeV1 => {
                format!("{timestamp}.{body}")
            }
            EnvelopeFormat::SlackV0 => format!("v0:{timestamp}:{body}"),
            EnvelopeFormat::GithubHmac => body.to_string(),
        };
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).ok()?;
        mac.update(signing_input.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        if env
            .signatures
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&expected))
        {
            return None;
        }
        let envelope_label = match webhook.envelope_format {
            EnvelopeFormat::Raw => "raw",
            EnvelopeFormat::StripeV1 => "stripe_v1",
            EnvelopeFormat::SlackV0 => "slack_v0",
            EnvelopeFormat::GithubHmac => "github_hmac",
        };
        let evidence = vec![
            Evidence::with(
                format!(
                    "Provided {} ({envelope_label}): {}",
                    webhook.signature_header, env.label
                ),
                format!(
                    "request.headers.{}",
                    webhook.signature_header.to_lowercase()
                ),
            ),
            Evidence::with(
                format!("Expected (HMAC-SHA256 over '{{timestamp}}.{{body}}'): {expected}"),
                "computed",
            ),
            Evidence::with(
                format!("Signing input length: {} bytes", signing_input.len()),
                "computed",
            ),
        ];
        // HMAC mismatch is dispositive: either secret, body, or timestamp prefix
        // differs. Rated higher than timestamp drift, which is inferential.
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Webhook signature does not match recomputed HMAC".into(),
            confidence: 0.92,
            evidence,
            next_steps: vec![
                "Confirm the active signing secret matches the one used by the sender.".into(),
                "Verify the receiver hashes the raw request body (not a re-serialised copy)."
                    .into(),
                "Inspect any proxy / middleware that may rewrite the body before validation."
                    .into(),
            ],
            escalation: "Recomputed HMAC differs from the provided signature. The most \
                         common causes are a rotated-but-not-deployed secret, a body \
                         being re-serialised (whitespace / key order changes), or a \
                         proxy mutating the request. Confirm with the customer which \
                         secret revision is active on their side."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 5 — webhook_timestamp_stale
//
// Computes the absolute drift between the timestamp the sender used
// (from the configured timestamp_header for raw envelopes, or from
// the envelope's `t=` field for Stripe v1) and the reference
// `now_unix` pinned in the case. Fires when drift > tolerance_seconds.
//
// Confidence tiers:
//   * drift > 10× tolerance  → 0.90 (systemic, almost certainly not skew)
//   * drift >  1× tolerance  → 0.85 (could be benign clock skew)
//
// Rated lower than `webhook_signature_mismatch` because clock skew has
// benign causes (NTP hiccup) while HMAC mismatch does not.
// ---------------------------------------------------------------------------

struct WebhookTimestampStale;

impl Rule for WebhookTimestampStale {
    fn id(&self) -> &str {
        "webhook_timestamp_stale"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let webhook = case.context.webhook.as_ref()?;
        let now = case.context.now_unix?;
        let provided_sig = header(&case.request.headers, &webhook.signature_header).unwrap_or("");
        let ts_raw = header(&case.request.headers, &webhook.timestamp_header).unwrap_or("");
        let env = parse_envelope(webhook.envelope_format, provided_sig, ts_raw);
        let ts = env.timestamp?;
        let drift = now - ts;
        if drift.abs() <= webhook.tolerance_seconds {
            return None;
        }
        let direction = if drift >= 0 { "behind" } else { "ahead of" };
        let (source_label, source_pointer) = match webhook.envelope_format {
            EnvelopeFormat::Raw | EnvelopeFormat::SlackV0 => (
                webhook.timestamp_header.clone(),
                format!(
                    "request.headers.{}",
                    webhook.timestamp_header.to_lowercase()
                ),
            ),
            EnvelopeFormat::StripeV1 => (
                format!("{} (stripe_v1 t=)", webhook.signature_header),
                format!(
                    "request.headers.{}",
                    webhook.signature_header.to_lowercase()
                ),
            ),
            // Unreachable: GithubHmac has no timestamp; the early
            // return at `let ts = env.timestamp?` prevents this match
            // from running. Keeping a reasonable label for safety.
            EnvelopeFormat::GithubHmac => (
                "github_hmac (no timestamp)".to_string(),
                format!(
                    "request.headers.{}",
                    webhook.signature_header.to_lowercase()
                ),
            ),
        };
        let evidence = vec![
            Evidence::with(
                format!(
                    "{}: {} ({} {} reference now)",
                    source_label,
                    ts,
                    drift.abs(),
                    direction
                ),
                source_pointer,
            ),
            Evidence::with(
                format!(
                    "Tolerance is {} seconds; observed drift {} seconds",
                    webhook.tolerance_seconds,
                    drift.abs()
                ),
                "case.context.webhook.tolerance_seconds",
            ),
        ];
        let confidence = if drift.abs() > webhook.tolerance_seconds * 10 {
            0.90
        } else {
            0.85
        };
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Webhook timestamp outside tolerance window".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Check NTP / clock skew between sender and receiver.".into(),
                "Confirm the timestamp header reflects the time the payload was signed, \
                 not the time it was forwarded."
                    .into(),
                "If retries are stored on disk before delivery, refresh the signature \
                 immediately before the actual send."
                    .into(),
            ],
            escalation: "Webhook timestamp is outside the configured tolerance. This \
                         often indicates clock skew, queued retries that re-send a \
                         long-stored payload, or a misconfigured replay window."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 6 — timeout_retry
//
// Walks the bundled `server.log` (text or JSON-lines, auto-detected
// per line) looking for timeout-bearing entries. Groups them by
// `request_id` so interleaved streams do not pool together (the
// negative `single_timeout_no_retry` and the positive
// `timeout_retry_partial_outage` both exercise this).
//
// Elapsed is *derived* from RFC3339 timestamp prefixes via
// `parse_timestamp_ms`, not read from a logged convenience field.
// This makes the rule survive logs that lack `total_elapsed_ms` and
// mirrors how a real support engineer would compute the number.
//
// Confidence tiers:
//   * derived elapsed > documented client_deadline_ms → 0.90
//   * max attempt observed ≥ 3 (retry exhaustion)     → 0.85
//   * client deadline documented but not exceeded     → 0.85
//   * just ≥ 2 timeouts, no deadline, attempt < 3     → 0.65
// ---------------------------------------------------------------------------

struct TimeoutRetry;

impl Rule for TimeoutRetry {
    fn id(&self) -> &str {
        "timeout_retry"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let log = case.load_log()?;

        // Group timeouts by request_id so interleaved request streams do not
        // pollute each other's attempt counts. The rule fires for the worst
        // offender (most attempts; ties broken by total elapsed).
        struct Stream<'a> {
            request_id: String,
            timeouts: Vec<(u32, LogLine<'a>)>,
            max_attempt: u32,
            elapsed_ms: Option<u64>,
        }

        let mut streams: BTreeMap<String, Stream<'_>> = BTreeMap::new();
        let mut unknown_id_timeouts: Vec<(u32, LogLine<'_>)> = Vec::new();

        for (idx, raw) in log.lines().enumerate() {
            let line = LogLine::parse(raw);
            if !(line.contains_ci("timeout") || line.contains_ci("timed out")) {
                continue;
            }
            let line_no = (idx as u32) + 1;
            match line.field("request_id") {
                Some(rid) => {
                    let entry = streams.entry(rid.clone()).or_insert_with(|| Stream {
                        request_id: rid,
                        timeouts: Vec::new(),
                        max_attempt: 0,
                        elapsed_ms: None,
                    });
                    if let Some(a) = line.field("attempt").and_then(|s| s.parse::<u32>().ok()) {
                        entry.max_attempt = entry.max_attempt.max(a);
                    }
                    entry.timeouts.push((line_no, line));
                }
                None => unknown_id_timeouts.push((line_no, line)),
            }
        }

        let total_timeouts: usize =
            streams.values().map(|s| s.timeouts.len()).sum::<usize>() + unknown_id_timeouts.len();
        if total_timeouts < 2 {
            return None;
        }

        // Derive elapsed_ms per stream as the span from the first to the last
        // log line bearing this request_id (not just timeout-bearing lines —
        // the final retries-exhausted error usually has a different reason
        // string but is part of the same customer-facing duration). This
        // replaces a hand-logged convenience field with a measurement.
        for stream in streams.values_mut() {
            let mut min_ms: Option<i64> = None;
            let mut max_ms: Option<i64> = None;
            for raw in log.lines() {
                let line = LogLine::parse(raw);
                if line.field("request_id").as_deref() != Some(stream.request_id.as_str()) {
                    continue;
                }
                if let Some(ms) = parse_timestamp_ms(raw) {
                    min_ms = Some(min_ms.map_or(ms, |m| m.min(ms)));
                    max_ms = Some(max_ms.map_or(ms, |m| m.max(ms)));
                }
            }
            // Subtraction is safe — `b > a` guarantees non-negative;
            // the cast to u64 stays in range because elapsed_ms can
            // never exceed `i64::MAX` on any plausible log span.
            if let (Some(a), Some(b)) = (min_ms, max_ms) {
                if b > a {
                    stream.elapsed_ms = Some((b - a) as u64);
                }
            }
        }

        // Pick the worst offender: most timeouts, then highest max_attempt.
        let primary_stream = streams
            .values()
            .max_by_key(|s| (s.timeouts.len(), s.max_attempt));

        let mut evidence: Vec<Evidence> = Vec::new();
        if let Some(s) = primary_stream {
            evidence.push(Evidence::with(
                format!(
                    "request_id={} accounts for {} timeout entries (max attempt={})",
                    s.request_id,
                    s.timeouts.len(),
                    s.max_attempt
                ),
                "server.log",
            ));
            for (line_no, line) in s.timeouts.iter().take(4) {
                evidence.push(Evidence::at_line(
                    format!("timeout entry: {}", truncate(line.raw(), 160)),
                    "server.log",
                    *line_no,
                ));
            }
            if let Some(elapsed) = s.elapsed_ms {
                evidence.push(Evidence::with(
                    format!(
                        "elapsed (derived from log timestamps): {} ms across {} attempts",
                        elapsed,
                        s.timeouts.len()
                    ),
                    "computed",
                ));
            }
        }
        // Count distinct request_ids in the *whole* log, not just streams
        // with timeouts. If more than one is present, the rule has actively
        // resisted pooling timeouts across unrelated requests.
        let all_request_ids: std::collections::BTreeSet<String> = log
            .lines()
            .filter_map(|raw| LogLine::parse(raw).field("request_id"))
            .collect();
        if all_request_ids.len() > 1 {
            evidence.push(Evidence::with(
                format!(
                    "log contains {} distinct request_ids; rule grouped timeouts by request_id rather than pooling",
                    all_request_ids.len()
                ),
                "server.log",
            ));
        }

        let mut confidence: f32 = 0.65;
        if let Some(s) = primary_stream {
            if s.max_attempt >= 3 {
                confidence = confidence.max(0.85);
                evidence.push(Evidence::with(
                    format!(
                        "max attempt observed: {} (suggests retry exhaustion)",
                        s.max_attempt
                    ),
                    "server.log",
                ));
            }
            if let (Some(elapsed), Some(deadline)) = (s.elapsed_ms, case.context.client_deadline_ms)
            {
                if elapsed > deadline {
                    confidence = confidence.max(0.90);
                    evidence.push(Evidence::with(
                        format!(
                            "derived elapsed {} ms exceeds documented client deadline {} ms",
                            elapsed, deadline
                        ),
                        "computed",
                    ));
                }
            }
        }
        if let Some(deadline_ms) = case.context.client_deadline_ms {
            evidence.push(Evidence::with(
                format!("documented client deadline: {deadline_ms} ms"),
                "case.context.client_deadline_ms",
            ));
            confidence = confidence.max(0.85);
        }

        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Upstream timeout with retries exhausted".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Inspect upstream latency for the affected endpoint.".into(),
                "Verify retry policy (max attempts, backoff, jitter).".into(),
                "If the deadline is shorter than upstream p99, raise it or reduce work.".into(),
            ],
            escalation: "Client retried the request multiple times before failing. \
                         Confirm whether upstream latency spiked, whether the retry \
                         budget is appropriate for the documented client deadline, and \
                         whether idempotency keys protect against duplicate side \
                         effects on retry."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 7 — config_dns_error
//
// Compares the request URL's host (and scheme) against the
// documented `expected_base_url`. The rule is interesting because of
// the near-miss detector: if the two hosts differ in exactly one
// dot-delimited label by Hamming distance ≤ 2, the rule reports
// "near-miss label: X differs from documented Y by ≤2 chars
// (typo?)" with confidence 0.90. This is what catches
// `acme-co.exemple` vs `acme-co.example`.
//
// Confidence tiers:
//   * one-label near-miss (typo) → 0.90
//   * scheme mismatch            → 0.80
//   * host mismatch with no near-miss → 0.75
// ---------------------------------------------------------------------------

struct ConfigDnsError;

impl Rule for ConfigDnsError {
    fn id(&self) -> &str {
        "config_dns_error"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let expected_base = case.context.expected_base_url.as_ref()?;
        let expected = Url::parse(expected_base).ok()?;
        let actual = Url::parse(&case.request.url).ok()?;
        let exp_host = expected.host_str()?;
        let act_host = actual.host_str()?;
        if act_host == exp_host && actual.scheme() == expected.scheme() {
            return None;
        }
        let mut evidence = vec![
            Evidence::with(format!("Request host: {act_host}"), "request.url"),
            Evidence::with(
                format!("Documented base host: {exp_host}"),
                "case.context.expected_base_url",
            ),
        ];
        let mut confidence: f32 = 0.75;
        if actual.scheme() != expected.scheme() {
            evidence.push(Evidence::with(
                format!(
                    "Scheme differs: request={}, expected={}",
                    actual.scheme(),
                    expected.scheme()
                ),
                "request.url",
            ));
            confidence = confidence.max(0.80);
        }
        if let Some(hint) = near_miss_hint(act_host, exp_host) {
            evidence.push(Evidence::with(hint, "computed"));
            confidence = confidence.max(0.90);
        }
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "API base URL or hostname does not match documented endpoint".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Confirm the API base URL in the customer's environment configuration.".into(),
                "Run `dig` / `nslookup` against the documented host to rule out DNS issues.".into(),
                "Check for environment variable overrides (staging vs production).".into(),
            ],
            escalation: "Customer is targeting a host that does not match the documented \
                         API base. The most common causes are a stale base-URL config, a \
                         staging endpoint left in production, or a typo in a TLD or \
                         subdomain. Verify the deploying revision before assuming a DNS \
                         outage."
                .into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rule 8 — idempotency_collision
//
// Recomputes SHA-256 of the current request body and compares
// against `context.idempotency.stored_body_sha256` — the hash the
// server stored under this `Idempotency-Key` on the first send. A
// mismatch means the customer reused the key with a different body,
// which Stripe and many real APIs reject with 422.
//
// Confidence tiers:
//   * 422 + hash mismatch          → 0.93 (Stripe-shape)
//   * other 4xx + hash mismatch    → 0.80
//   * non-error response, mismatch → 0.70
// ---------------------------------------------------------------------------

struct IdempotencyCollision;

impl Rule for IdempotencyCollision {
    fn id(&self) -> &str {
        "idempotency_collision"
    }
    fn evaluate(&self, case: &Case) -> Option<Diagnosis> {
        let idem = case.context.idempotency.as_ref()?;
        let key = header(&case.request.headers, &idem.header)?;
        let body = case.request.body.as_deref().unwrap_or("");
        let mut hasher = Sha256::new();
        hasher.update(body.as_bytes());
        let actual = hex::encode(hasher.finalize());
        if actual.eq_ignore_ascii_case(&idem.stored_body_sha256) {
            return None;
        }
        let status = case.response.as_ref().map(|r| r.status).unwrap_or(0);
        let mut evidence = vec![
            Evidence::with(
                format!("Idempotency-Key: {key}"),
                format!("request.headers.{}", idem.header.to_lowercase()),
            ),
            Evidence::with(
                format!("Stored body SHA-256: {}", idem.stored_body_sha256),
                "case.context.idempotency.stored_body_sha256",
            ),
            Evidence::with(format!("Current body SHA-256: {actual}"), "computed"),
            Evidence::with(
                format!("Current body length: {} bytes", body.len()),
                "request.body",
            ),
        ];
        let confidence = if status == 422 {
            evidence.push(Evidence::with(
                "Response status 422 confirms server rejected duplicate-key with different body",
                "response.status",
            ));
            0.93
        } else if (400..500).contains(&status) {
            0.80
        } else {
            0.70
        };
        Some(Diagnosis {
            rule_id: self.id().into(),
            likely_cause: "Idempotency-Key reused with a different request body".into(),
            confidence,
            evidence,
            next_steps: vec![
                "Generate a fresh Idempotency-Key for any logically new request.".into(),
                "If retrying, send byte-identical body bytes used on the first attempt.".into(),
                "Check whether a serialiser or middleware is adding fields between attempts."
                    .into(),
            ],
            escalation: "Customer reused an Idempotency-Key with a different body, so the \
                         server returned its stored-body-mismatch error. Confirm whether \
                         their retry logic captures the body before its first send and \
                         replays the same bytes, or whether a logging / proxy layer is \
                         re-serialising between attempts."
                .into(),
        })
    }
}

/// Heuristic that flags hostname near-misses worth reporting as
/// "this looks like a typo, not a configuration drift."
///
/// Two hosts with the same number of dot-delimited labels that
/// differ in exactly one label, where the differing labels are the
/// same length and within Hamming distance 2, are reported as a
/// near-miss. This catches `acme-co.exemple` vs `acme-co.example`
/// without firing on `staging-api.acme-co.example` vs
/// `api.acme-co.example` (different label count).
///
/// As a fallback, when the suffix-most labels differ outright (TLD
/// mismatch like `.local` vs `.example`), a TLD-differs hint is
/// emitted instead.
fn near_miss_hint(actual: &str, expected: &str) -> Option<String> {
    let a_parts: Vec<&str> = actual.rsplit('.').collect();
    let e_parts: Vec<&str> = expected.rsplit('.').collect();
    if a_parts.len() == e_parts.len() {
        let mut diffs = 0usize;
        let mut diff_label: Option<(&str, &str)> = None;
        for (a, e) in a_parts.iter().zip(e_parts.iter()) {
            if a != e {
                diffs += 1;
                diff_label = Some((a, e));
            }
        }
        if diffs == 1 {
            let (a, e) = diff_label?;
            // Same length + Hamming ≤ 2 captures realistic typos
            // ("exemple" / "example" — one letter swap) without
            // matching unrelated short labels like "api" vs "abc".
            if a.len() == e.len() && hamming(a, e) <= 2 {
                return Some(format!(
                    "near-miss label: '{a}' differs from documented '{e}' by ≤2 chars (typo?)"
                ));
            }
        }
    }
    if !actual.ends_with(expected.split('.').next_back().unwrap_or("")) {
        return Some(format!(
            "TLD differs: request '{actual}' vs documented '{expected}'"
        ));
    }
    None
}

/// Number of differing characters between two strings of equal length.
///
/// Used by [`near_miss_hint`] to decide whether two same-length
/// labels are close enough to count as a typo. The chars are walked
/// pairwise; differences are counted. The function does not handle
/// unequal-length strings — callers gate on length first.
fn hamming(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).filter(|(x, y)| x != y).count()
}

/// Cap a string at `max` bytes, appending an ellipsis if truncated.
///
/// Used in evidence messages so a noisy log line never blows up the
/// human report. Truncation is byte-based (cheap); since logs are
/// ASCII-clean, the resulting string is still valid UTF-8.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}\u{2026}", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// Unit tests for private helpers.
//
// Mutation testing (`cargo mutants --file src/rules.rs`) flagged the
// helpers below as the largest coverage gaps in the suite — their
// arithmetic / boundary mutants survive when nothing tests the
// helpers directly. These tests exist to kill those mutants.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod private_helper_tests {
    use super::*;

    // days_from_civil: exact reference values from Hinnant's table.
    // Each row verifies one mutation class (year boundary, leap year,
    // March-based month mapping, era boundary).

    #[test]
    fn days_from_civil_unix_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn days_from_civil_one_day_after_epoch() {
        assert_eq!(days_from_civil(1970, 1, 2), 1);
    }

    #[test]
    fn days_from_civil_one_year_after_epoch() {
        assert_eq!(days_from_civil(1971, 1, 1), 365);
    }

    #[test]
    fn days_from_civil_2000_leap_day() {
        // 2000 is a century divisible by 400 → leap year.
        // Days from 1970-01-01 to 2000-02-29:
        //   30 years × 365 + 8 leap days (1972, 76, 80, 84, 88, 92, 96, 2000-Feb-29 not yet)
        //   = 10950 + 7 = 10957 to 2000-01-01
        //   + 31 (Jan) + 29 (Feb 1..29) - 1 (zero-indexed Feb 29) = 10957 + 59 = 11016
        // Verified via Python: datetime.date(2000, 2, 29).toordinal() - datetime.date(1970, 1, 1).toordinal()
        assert_eq!(days_from_civil(2000, 2, 29), 11016);
    }

    #[test]
    fn days_from_civil_2100_not_leap() {
        // 2100 is divisible by 100 but not 400 → not a leap year.
        // March 1, 2100 should be exactly 365 + ... days (no extra leap).
        // We just check March 1 lands one day after Feb 28.
        let feb28 = days_from_civil(2100, 2, 28);
        let mar01 = days_from_civil(2100, 3, 1);
        assert_eq!(mar01 - feb28, 1, "2100 must not be a leap year");
    }

    #[test]
    fn days_from_civil_2400_leap() {
        // 2400 is divisible by 400 → leap year.
        let feb29 = days_from_civil(2400, 2, 29);
        let mar01 = days_from_civil(2400, 3, 1);
        assert_eq!(mar01 - feb29, 1, "2400 must be a leap year");
    }

    #[test]
    fn days_from_civil_pre_epoch() {
        // 1969-12-31 is one day before the epoch → -1.
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    // parse_timestamp_ms: exercises both the date parser (above) and
    // the time-of-day parser. Cross-day spans must produce monotonic
    // milliseconds.

    #[test]
    fn parse_timestamp_ms_unix_epoch_zero() {
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00.000Z"), Some(0));
    }

    #[test]
    fn parse_timestamp_ms_one_second_after_epoch() {
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:01.000Z"), Some(1000));
    }

    #[test]
    fn parse_timestamp_ms_pads_short_fractions() {
        // ".5" must mean 500 ms, not 5 ms.
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00.5Z"), Some(500));
    }

    #[test]
    fn parse_timestamp_ms_returns_none_on_garbage() {
        assert_eq!(parse_timestamp_ms("not a timestamp"), None);
        assert_eq!(parse_timestamp_ms(""), None);
    }

    #[test]
    fn parse_timestamp_ms_rejects_invalid_month() {
        // Month 13 is rejected by the upfront range guard.
        assert_eq!(parse_timestamp_ms("1970-13-01T00:00:00.000Z"), None);
    }

    #[test]
    fn parse_timestamp_ms_cross_midnight_is_monotone() {
        let before = parse_timestamp_ms("2026-12-31T23:59:59.500Z").unwrap();
        let after = parse_timestamp_ms("2027-01-01T00:00:01.500Z").unwrap();
        assert_eq!(after - before, 2000, "cross-midnight span must be 2 s");
    }

    // hamming: exhaustive small-input coverage.

    #[test]
    fn hamming_identical_strings() {
        assert_eq!(hamming("abc", "abc"), 0);
    }

    #[test]
    fn hamming_one_char_diff() {
        assert_eq!(hamming("abc", "abd"), 1);
    }

    #[test]
    fn hamming_all_diff() {
        assert_eq!(hamming("abc", "xyz"), 3);
    }

    #[test]
    fn hamming_empty_strings() {
        assert_eq!(hamming("", ""), 0);
    }

    // near_miss_hint: covers the typo branch, the TLD-differs branch,
    // and the no-hint branch.

    #[test]
    fn near_miss_hint_typo_label() {
        let hint = near_miss_hint("api.acme.exemple", "api.acme.example");
        let h = hint.expect("typo near-miss must produce a hint");
        assert!(h.contains("near-miss"), "{h}");
    }

    #[test]
    fn near_miss_hint_completely_different_tld() {
        let hint = near_miss_hint("api.acme.local", "api.acme.example");
        let h = hint.expect("TLD-differs must produce a hint");
        assert!(h.contains("TLD differs"), "{h}");
    }

    #[test]
    fn near_miss_hint_label_count_differs() {
        // staging.api.acme.example has 4 labels; api.acme.example has 3.
        // No near-miss heuristic applies; depending on TLD comparison
        // this can still emit a TLD-differs hint, but only when the
        // suffix-most label genuinely differs. For matching TLDs the
        // result is `None`.
        let hint = near_miss_hint("staging.api.acme.example", "api.acme.example");
        // Either None or a hint that names a real divergence.
        if let Some(h) = hint {
            assert!(h.contains("TLD") || h.contains("near-miss"), "{h}");
        }
    }

    // truncate: boundary on `max`.

    #[test]
    fn truncate_under_limit_passes_through() {
        assert_eq!(truncate("hi", 10), "hi");
    }

    #[test]
    fn truncate_at_limit_passes_through() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_over_limit_appends_ellipsis() {
        assert_eq!(truncate("hello!", 5), "hello\u{2026}");
    }

    // parse_envelope: per-format dispatch.

    #[test]
    fn parse_envelope_raw_strips_sha256_prefix() {
        let env = parse_envelope(EnvelopeFormat::Raw, "sha256=deadbeef", "1700000000");
        assert_eq!(env.signatures, vec!["deadbeef".to_string()]);
        assert_eq!(env.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn parse_envelope_stripe_v1_collects_v1_and_v0() {
        let env = parse_envelope(
            EnvelopeFormat::StripeV1,
            "t=1700000000,v1=aaaa,v0=bbbb",
            "ignored",
        );
        assert_eq!(env.signatures, vec!["aaaa".to_string(), "bbbb".to_string()]);
        assert_eq!(env.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn parse_envelope_slack_v0_strips_prefix() {
        let env = parse_envelope(EnvelopeFormat::SlackV0, "v0=cafef00d", "1700000000");
        assert_eq!(env.signatures, vec!["cafef00d".to_string()]);
        assert_eq!(env.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn parse_envelope_github_hmac_has_no_timestamp() {
        let env = parse_envelope(
            EnvelopeFormat::GithubHmac,
            "sha256=feedface",
            "this should be ignored",
        );
        assert_eq!(env.signatures, vec!["feedface".to_string()]);
        assert_eq!(env.timestamp, None, "GitHub envelope claims no timestamp");
    }
}
