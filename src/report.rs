// SPDX-License-Identifier: Apache-2.0

//! [`Report`] — what `diagnose` returns and the CLI prints.
//!
//! A report is a thin wrapper around a top-confidence [`Diagnosis`]
//! plus zero or more `also_considered` alternatives. It owns the
//! curl-shaped reproduction string and the case-level metadata that
//! is rendered in both the human and JSON formats.
//!
//! Every formatter here must produce **byte-stable** output:
//! re-running `diagnose` against the same case must produce a
//! `Report` whose [`Report::render`] returns the exact same bytes,
//! every time, on every machine. The snapshot tests in
//! `tests/snapshots.rs` enforce this contract.

use crate::cases::{Case, Severity};
use crate::evidence::Evidence;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Output format for [`Report::render`].
///
/// The CLI exposes this via `--format`; library callers can pick
/// whichever they need. Both formats are byte-stable for a given
/// `Report`.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Format {
    /// Human-readable plain text. The shape a support engineer pastes
    /// into a ticket: `CASE`, `SEVERITY`, `LIKELY CAUSE`, `CONFIDENCE`,
    /// `RULE`, `EVIDENCE`, `REPRODUCTION`, `NEXT STEPS`,
    /// `ESCALATION NOTE`, optional `ALSO CONSIDERED`.
    #[default]
    Human,
    /// Pretty-printed JSON. Keys match the `Report` / `Diagnosis`
    /// field names; suitable for piping into `jq` or another tool.
    Json,
}

/// One firing diagnosis: the rule's claim, its confidence, the
/// supporting evidence, and the rule's recommended remediation.
///
/// Every field is owned (no borrows) so a `Diagnosis` can be cloned
/// across rule boundaries and serialised cheaply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[must_use = "a Diagnosis is meaningless until rendered, inspected, or returned"]
pub struct Diagnosis {
    /// Stable identifier of the rule that produced this diagnosis
    /// (e.g. `"auth_missing"`). Matches `Rule::id`.
    pub rule_id: String,
    /// One-sentence summary of the rule's claim. Rendered as the
    /// `LIKELY CAUSE:` line.
    pub likely_cause: String,
    /// Posterior confidence in the diagnosis, in `[0.0, 1.0]`. The
    /// rubric for these values lives in `docs/confidence_model.md`
    /// and is held accountable by `tests/calibration.rs`.
    pub confidence: f32,
    /// Supporting observations. Each is a single sentence with an
    /// optional source pointer; the `explain` subcommand surfaces the
    /// pointers so the diagnosis can be audited.
    pub evidence: Vec<Evidence>,
    /// Customer-facing remediation steps in priority order.
    pub next_steps: Vec<String>,
    /// Engineering-facing escalation paragraph. Names the divergence
    /// space and the artefacts the on-call engineer needs.
    pub escalation: String,
}

/// Top-level result of [`crate::rules::diagnose`].
///
/// `primary` is `None` when no rule fired with confidence ≥ 0.6 (the
/// classification threshold). `also_considered` is sorted by
/// descending confidence and capped above by the primary's confidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[must_use = "a Report should be rendered, inspected, or its exit_code propagated"]
pub struct Report {
    /// Stable name of the case being diagnosed (matches `Case::name`).
    pub case_name: String,
    /// Severity tag from the case (mirrored verbatim).
    pub severity: Severity,
    /// Top-confidence diagnosis, if any rule fired above threshold.
    pub primary: Option<Diagnosis>,
    /// Other rules that fired, sorted by descending confidence and
    /// bounded above by `primary.confidence`. Empty when only one
    /// rule fired (or none did).
    #[serde(default)]
    pub also_considered: Vec<Diagnosis>,
    /// Pre-rendered curl reproduction string. Header order is
    /// alphabetical; the body is inlined with `--data-raw` so the
    /// string is the same on every machine (no absolute paths).
    pub reproduction: String,
}

impl Report {
    /// Process exit code the CLI should return for this report.
    ///
    /// `0` if a primary diagnosis fired with confidence ≥ 0.60, `1`
    /// if the case is unclassified or low-confidence. The threshold
    /// matches the human formatter's "No rule matched" message.
    /// Higher-level "bad input" errors are mapped to exit code `2`
    /// by the CLI itself, not here.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use api_debug_lab::{diagnose, Case};
    /// use std::path::Path;
    ///
    /// let case = Case::load("auth_missing", Path::new("fixtures"))?;
    /// assert_eq!(diagnose(&case).exit_code(), 0);
    /// # Ok::<(), api_debug_lab::CaseLoadError>(())
    /// ```
    #[must_use = "the CLI must propagate this exit code via std::process::ExitCode"]
    pub fn exit_code(&self) -> i32 {
        match &self.primary {
            Some(d) if d.confidence >= 0.6 => 0,
            _ => 1,
        }
    }

    /// Render the report in the requested [`Format`].
    ///
    /// Both formats are byte-stable: the same input always produces
    /// the same output bytes. The JSON format uses pretty-printing
    /// so diffs in PRs are legible.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use api_debug_lab::{diagnose, Case, Format};
    /// use std::path::Path;
    ///
    /// let case = Case::load("auth_missing", Path::new("fixtures"))?;
    /// let report = diagnose(&case);
    /// let human = report.render(Format::Human);
    /// assert!(human.starts_with("CASE:"));
    /// # Ok::<(), api_debug_lab::CaseLoadError>(())
    /// ```
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Human => self.render_human(),
            Format::Json => {
                serde_json::to_string_pretty(self).unwrap_or_else(|_| String::from("{}"))
            }
        }
    }

    /// Build the human-readable plain-text rendering.
    ///
    /// Private; callers go through [`Self::render`].
    fn render_human(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "CASE: {}", self.case_name);
        let _ = writeln!(out, "SEVERITY: {}", self.severity.as_str());
        match &self.primary {
            Some(d) => {
                let _ = writeln!(out, "LIKELY CAUSE: {}", d.likely_cause);
                let _ = writeln!(out, "CONFIDENCE: {:.2}", d.confidence);
                let _ = writeln!(out, "RULE: {}", d.rule_id);
                let _ = writeln!(out);
                let _ = writeln!(out, "EVIDENCE:");
                for e in &d.evidence {
                    let _ = writeln!(out, "- {}", e.message);
                }
                let _ = writeln!(out);
                let _ = writeln!(out, "REPRODUCTION:");
                let _ = writeln!(out, "{}", self.reproduction);
                let _ = writeln!(out);
                let _ = writeln!(out, "NEXT STEPS:");
                for (i, step) in d.next_steps.iter().enumerate() {
                    let _ = writeln!(out, "{}. {}", i + 1, step);
                }
                let _ = writeln!(out);
                let _ = writeln!(out, "ESCALATION NOTE:");
                let _ = writeln!(out, "{}", d.escalation);
            }
            None => {
                let _ = writeln!(out, "LIKELY CAUSE: unclassified");
                let _ = writeln!(out, "CONFIDENCE: 0.00");
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "No rule matched with confidence \u{2265} 0.60. \
                     Inspect fixtures by hand and consider adding a new rule."
                );
            }
        }
        if !self.also_considered.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "ALSO CONSIDERED:");
            for d in &self.also_considered {
                let _ = writeln!(
                    out,
                    "- {} (confidence {:.2}): {}",
                    d.rule_id, d.confidence, d.likely_cause
                );
            }
        }
        out
    }
}

/// Build a deterministic curl reproduction string for a case.
///
/// The output is ready to paste into a shell:
///
/// ```text
/// curl -X POST https://api.acme-co.example/v1/events \
///   -H "content-type: application/json" \
///   -H "user-agent: acme-client/0.4.1" \
///   --data-raw '{"event":"order.created","order_id":"ord_8KZ"}'
/// ```
///
/// Headers are emitted in alphabetical order; the body is inlined
/// with `--data-raw` (single-quoted with embedded single-quotes
/// shell-escaped) rather than referenced via `--data-binary @file`.
/// The latter would bake an absolute path into the output and break
/// snapshot stability across machines.
pub fn reproduction(case: &Case) -> String {
    let mut out = String::new();
    let _ = write!(out, "curl -X {} {}", case.request.method, case.request.url);
    let mut keys: Vec<&String> = case.request.headers.keys().collect();
    keys.sort();
    for k in keys {
        let v = &case.request.headers[k];
        let _ = write!(out, " \\\n  -H \"{k}: {v}\"");
    }
    if let Some(body) = case.request.body.as_deref() {
        // Shell-escape only the single-quote, since we wrap the body
        // in single quotes. This is sufficient for paste-into-bash;
        // it is not a general-purpose shell escaper.
        let escaped = body.replace('\'', "'\\''");
        let _ = write!(out, " \\\n  --data-raw '{escaped}'");
    }
    out
}
