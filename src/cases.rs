// SPDX-License-Identifier: Apache-2.0

//! [`Case`] — the input fixture every rule consumes.
//!
//! A *case* is a snapshot of one customer-visible API failure: the
//! request bytes (method, URL, headers, body), an optional response
//! (status, headers, body), an optional sibling `server.log`, an
//! optional sibling `secret.txt` for HMAC checks, and a free-form
//! [`Context`] block carrying anything the rules need that isn't part
//! of the wire protocol (auth-required flag, expected base URL,
//! webhook envelope shape, idempotency hash, client deadline, pinned
//! `now_unix`).
//!
//! Cases are laid out on disk one-directory-per-case under
//! `fixtures/cases/<name>/`. Each directory is self-contained:
//! `case.json` is the structured data, `server.log` is the bundled
//! log (text or JSON-lines), `secret.txt` is the HMAC secret. This
//! shape is deliberate: a real support engineer can drop a customer's
//! captured artefacts into a directory of the same shape and run the
//! diagnostic against it via [`Case::load`] or `api-debug-lab corpus`.
//!
//! ## Schema
//!
//! Every `case.json` is validated against
//! `fixtures/cases.schema.json` (JSON Schema Draft 2020-12) by
//! `tests/schema.rs`. The schema is the wire-level contract; this
//! module is the deserialised mirror of it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors returned by [`Case::load`].
///
/// All variants carry the path the loader was operating on so the CLI
/// can produce actionable error messages.
#[derive(Debug, Error)]
pub enum CaseLoadError {
    /// Filesystem-level failure reading the `case.json` file.
    #[error("could not read case file {path}: {source}")]
    Io {
        /// Absolute path the loader attempted to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// `case.json` was found but did not deserialise into a [`Case`].
    #[error("could not parse case file {path}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying serde error (carries line / column).
        source: serde_json::Error,
    },

    /// The provided name resolved to neither a file, a directory, nor
    /// a known fixture under `fixtures/cases/` or `fixtures/cases/_negatives/`.
    #[error("could not resolve case name {0}: no fixture directory found")]
    UnknownCase(String),
}

/// Customer-visible severity tag for a case.
///
/// The CLI prints this in the `SEVERITY:` line of the human report;
/// the JSON renderer serialises it lower-cased. The rule layer does
/// not consume severity — it is operator metadata, not a signal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Cosmetic or informational; no customer impact.
    Low,
    /// Customer-impacting but localised; not paging-grade.
    Medium,
    /// Production fire; treat as paging-grade.
    High,
}

impl Severity {
    /// Render the severity as the same lowercase token used in JSON.
    ///
    /// Useful for the human formatter (`SEVERITY: medium`) and for
    /// matching against tags in escalation notes.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// HTTP request as captured by the customer or the proxy.
///
/// `headers` is a [`BTreeMap`] for deterministic iteration — it ends
/// up in `curl` reproductions and in snapshot tests, both of which
/// require byte-stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// HTTP method, e.g. `"POST"`.
    pub method: String,
    /// Full request URL (scheme + host + path + query).
    pub url: String,
    /// Request headers. Header names should be lower-cased on disk so
    /// that case-insensitive lookups via [`header`] work consistently.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Raw request body. Stored as a string so HMAC verification sees
    /// exactly the bytes the client sent (no JSON re-serialisation).
    /// `None` means no body was sent.
    #[serde(default)]
    pub body: Option<String>,
}

/// HTTP response as observed by the customer.
///
/// Optional on the [`Case`]: a case captured before any response
/// arrived (e.g., a timeout) has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// HTTP status code (100–599).
    pub status: u16,
    /// Response headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Raw response body, if any.
    #[serde(default)]
    pub body: Option<String>,
}

/// Free-form context the rules consume in addition to the wire
/// request/response.
///
/// All fields are optional. Each rule documents which fields it
/// consults; a rule that does not see what it needs simply does not
/// fire. This is what lets the same `Case` shape serve multiple rules
/// without coupling them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    /// Whether the endpoint requires client authentication. The
    /// `auth_missing` rule consults this to decide whether a missing
    /// `Authorization` header is actually a problem.
    #[serde(default)]
    pub auth_required: bool,

    /// Documented API base URL the client *should* be hitting. Used
    /// by `config_dns_error` for hostname / TLD comparison.
    #[serde(default)]
    pub expected_base_url: Option<String>,

    /// Webhook context for cases that involve HMAC signing.
    #[serde(default)]
    pub webhook: Option<WebhookCtx>,

    /// Idempotency context for cases that involve `Idempotency-Key`
    /// reuse.
    #[serde(default)]
    pub idempotency: Option<IdempotencyCtx>,

    /// Documented per-request client deadline in milliseconds. Used by
    /// `timeout_retry` to decide whether the derived elapsed exceeds
    /// the customer-side budget.
    #[serde(default)]
    pub client_deadline_ms: Option<u64>,

    /// Reference "now" (unix seconds) for stale-timestamp checks.
    /// Pinning this in the fixture is what keeps `webhook_timestamp_stale`
    /// deterministic across CI runs — the rule never reads the system
    /// clock.
    #[serde(default)]
    pub now_unix: Option<i64>,
}

/// Selector for how a webhook signature header should be parsed,
/// and the resulting HMAC signing-input shape.
///
/// Each variant maps to a real-world signing scheme used by a major
/// developer-facing API. Adding a new variant means: extending this
/// enum, extending `parse_envelope` in `src/rules.rs`, extending the
/// `signing_input` match in `WebhookSignatureMismatch::evaluate`, and
/// extending the `envelope_format` enum in `cases.schema.json`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeFormat {
    /// Header value is a raw hex digest, optionally prefixed `sha256=`.
    /// Timestamp comes from a separate `timestamp_header`.
    /// Signing input: `"{ts}.{body}"`.
    #[default]
    Raw,
    /// Stripe-style envelope: `t=<unix_ts>,v1=<sig>,v0=<sig>,...`.
    /// Timestamp comes from the envelope's `t=` field; `timestamp_header`
    /// is ignored.
    /// Signing input: `"{ts}.{body}"`.
    StripeV1,
    /// Slack v0 envelope: `X-Slack-Signature: v0=<hex>`. Timestamp
    /// comes from a separate `X-Slack-Request-Timestamp` header.
    /// Signing input: `"v0:{ts}:{body}"`.
    SlackV0,
    /// GitHub-style HMAC: `X-Hub-Signature-256: sha256=<hex>`. There
    /// is no timestamp claim; `webhook_timestamp_stale` cannot fire.
    /// Signing input: `{body}` (raw body, no prefix).
    GithubHmac,
}

/// Webhook context for a case that involves HMAC signing.
///
/// `secret_path` resolves relative to the case's `fixture_dir` and is
/// loaded lazily by [`Case::load_secret`] only when a webhook rule
/// fires (so non-webhook fixtures need no on-disk secret file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookCtx {
    /// Path to the signing secret, relative to the fixture directory.
    /// The file is read verbatim; its trailing newline (if any) is
    /// stripped by [`Case::load_secret`].
    pub secret_path: String,
    /// Name of the header that carries the signature. For
    /// [`EnvelopeFormat::Raw`] this is the digest header; for
    /// [`EnvelopeFormat::StripeV1`] it is the envelope header that
    /// contains both the digest and the timestamp.
    pub signature_header: String,
    /// Name of the header that carries the timestamp the sender hashed.
    /// Ignored when `envelope_format` is `stripe_v1` (the timestamp
    /// then comes from the envelope's `t=` field).
    pub timestamp_header: String,
    /// Maximum acceptable absolute drift (seconds) between
    /// [`Context::now_unix`] and the timestamp the sender used.
    pub tolerance_seconds: i64,
    /// How the signature header should be parsed. Defaults to
    /// [`EnvelopeFormat::Raw`] so v0.1.0 fixtures continue to validate
    /// without changes.
    #[serde(default)]
    pub envelope_format: EnvelopeFormat,
}

/// Idempotency context for a case where an `Idempotency-Key` is in
/// play.
///
/// Real APIs (Stripe, many fintech providers) store the SHA-256 of the
/// body that arrived under a given key. A retry with the same key but
/// a different body is rejected. The `idempotency_collision` rule
/// recomputes the digest of the current request body and compares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyCtx {
    /// Name of the idempotency-key header (e.g., `"idempotency-key"`).
    pub header: String,
    /// Hex-encoded SHA-256 of the body the server originally stored
    /// under this idempotency key. Must be exactly 64 hex characters.
    pub stored_body_sha256: String,
}

/// One bundled (or user-supplied) failure case.
///
/// Construct via [`Case::load`]; do not deserialise directly because
/// the loader populates `fixture_dir` and `log_path` from the on-disk
/// layout, which serde alone cannot do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// Stable identifier; matches the fixture directory name.
    pub name: String,
    /// One-sentence description of what the fixture demonstrates.
    pub description: String,
    /// Customer-facing severity tag. Not consumed by rules.
    pub severity: Severity,
    /// HTTP request bytes captured for this case.
    pub request: Request,
    /// HTTP response bytes, if any. `None` means the case captures a
    /// pre-response failure (typical for timeouts).
    #[serde(default)]
    pub response: Option<Response>,
    /// Free-form context the rules consume.
    #[serde(default)]
    pub context: Context,
    /// Ground-truth label: the rule that should fire as primary on
    /// this case, or `None` if the case must remain unclassified.
    /// Used by `tests/calibration.rs` and `tests/calibration_regression.rs`
    /// as the single source of truth. Optional on disk; cases without
    /// a label are excluded from the calibration corpus.
    #[serde(default)]
    pub expected_rule_id: Option<String>,
    /// Path to a sibling `server.log`, if present. Populated by
    /// [`Case::load`]; not part of `case.json` on disk.
    #[serde(skip)]
    pub log_path: Option<PathBuf>,
    /// Directory containing the loaded `case.json`. Populated by
    /// [`Case::load`]; used to resolve `secret_path` and to walk
    /// sibling files (`server.log`, `secret.txt`).
    #[serde(skip)]
    pub fixture_dir: PathBuf,
}

impl Case {
    /// Load a case by name or by path.
    ///
    /// The lookup order is:
    ///
    /// 1. If `name_or_path` points at an existing file, load that file.
    /// 2. If it points at an existing directory, load `<dir>/case.json`.
    /// 3. Otherwise treat it as a name and resolve against
    ///    `<fixtures_root>/cases/<name>/case.json` first, then
    ///    `<fixtures_root>/cases/_negatives/<name>/case.json`.
    ///
    /// The third step is what lets `api-debug-lab diagnose
    /// upstream_401` find a negative fixture without the caller having
    /// to type the underscore-prefix path.
    ///
    /// On success, `fixture_dir` is set to the directory containing
    /// the loaded `case.json` and `log_path` is set when a sibling
    /// `server.log` exists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use api_debug_lab::Case;
    /// use std::path::Path;
    ///
    /// let case = Case::load("auth_missing", Path::new("fixtures"))?;
    /// assert_eq!(case.name, "auth_missing");
    /// # Ok::<(), api_debug_lab::CaseLoadError>(())
    /// ```
    pub fn load(name_or_path: &str, fixtures_root: &Path) -> Result<Self, CaseLoadError> {
        let candidate = Path::new(name_or_path);
        let json_path = if candidate.is_file() {
            candidate.to_path_buf()
        } else if candidate.is_dir() {
            candidate.join("case.json")
        } else {
            let dir = fixtures_root.join("cases").join(name_or_path);
            if dir.is_dir() {
                dir.join("case.json")
            } else {
                let neg_dir = fixtures_root
                    .join("cases")
                    .join("_negatives")
                    .join(name_or_path);
                if neg_dir.is_dir() {
                    neg_dir.join("case.json")
                } else {
                    return Err(CaseLoadError::UnknownCase(name_or_path.to_string()));
                }
            }
        };

        let raw = fs::read_to_string(&json_path).map_err(|source| CaseLoadError::Io {
            path: json_path.clone(),
            source,
        })?;
        let mut case: Case = serde_json::from_str(&raw).map_err(|source| CaseLoadError::Parse {
            path: json_path.clone(),
            source,
        })?;
        // The two on-disk-derived fields are populated here rather than
        // via serde so that a `Case` constructed in a test (e.g. for
        // proptest) does not need to fabricate plausible paths.
        case.fixture_dir = json_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let log_candidate = case.fixture_dir.join("server.log");
        if log_candidate.is_file() {
            case.log_path = Some(log_candidate);
        }
        Ok(case)
    }

    /// Read the sibling `server.log` if one is present.
    ///
    /// Returns `None` for cases that do not bundle a log. Reading is
    /// lazy: rules that do not consult logs (e.g. `auth_missing`) pay
    /// no I/O cost.
    pub fn load_log(&self) -> Option<String> {
        self.log_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())
    }

    /// Read the webhook signing secret (`fixture_dir/<secret_path>`).
    ///
    /// Returns `None` if the case has no webhook context or if the
    /// file cannot be read. The trailing newline (if any) is stripped
    /// so the secret bytes are exactly what the sender used.
    pub fn load_secret(&self) -> Option<Vec<u8>> {
        let webhook = self.context.webhook.as_ref()?;
        let path = self.fixture_dir.join(&webhook.secret_path);
        let raw = fs::read_to_string(path).ok()?;
        Some(raw.trim_end_matches('\n').as_bytes().to_vec())
    }
}

/// Enumerate the bundled positive fixtures.
///
/// Returns the names (one per directory) under
/// `<fixtures_root>/cases/`, sorted alphabetically and excluding any
/// directory whose name starts with `_` (the convention for negative
/// fixtures and other internal-only sets like `_calibration/`).
///
/// The `list-cases` subcommand calls this; the `corpus` subcommand
/// does not — corpus walks the tree directly and includes negatives.
pub fn list_cases(fixtures_root: &Path) -> Vec<String> {
    let cases_dir = fixtures_root.join("cases");
    let Ok(entries) = fs::read_dir(&cases_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('_') {
                None
            } else if e.path().join("case.json").is_file() {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names
}

/// Case-insensitive header lookup.
///
/// HTTP header names are case-insensitive on the wire (RFC 9110). The
/// fixtures store them lower-cased by convention, but rules call
/// `header(headers, "Authorization")` and `header(headers, "x-signature")`
/// interchangeably — this helper makes both work.
///
/// Returns the value of the first matching header. Iteration order is
/// stable because [`BTreeMap`] is ordered, but in practice header
/// names are unique within a case fixture.
pub fn header<'a>(map: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    let target = name.to_ascii_lowercase();
    map.iter()
        .find(|(k, _)| k.to_ascii_lowercase() == target)
        .map(|(_, v)| v.as_str())
}
