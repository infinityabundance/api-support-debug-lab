// SPDX-License-Identifier: Apache-2.0

//! Per-rule unit tests with paired positive + negative fixtures.
//!
//! For every rule, two assertions:
//!
//! 1. The bundled positive fixture fires the rule with the documented
//!    confidence floor and the documented evidence markers.
//! 2. The matching negative fixture (under
//!    `fixtures/cases/_negatives/`) does *not* classify above the
//!    threshold — the rule has resisted shape-similarity from a
//!    case that would fool a naive grep-based classifier.
//!
//! Plus three structural tests: arbitration ordering on the
//! ambiguous webhook fixture, byte-stable determinism, and exit-code
//! mapping.

use std::path::PathBuf;

use api_debug_lab::cases::Case;
use api_debug_lab::rules::diagnose;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn load(name: &str) -> Case {
    Case::load(name, &fixtures_root()).expect("load fixture")
}

fn primary_id(name: &str) -> Option<String> {
    diagnose(&load(name)).primary.map(|d| d.rule_id)
}

fn primary_confidence(name: &str) -> f32 {
    diagnose(&load(name))
        .primary
        .map(|d| d.confidence)
        .unwrap_or(0.0)
}

// ---- positives ----

#[test]
fn auth_missing_fires_with_high_confidence() {
    let report = diagnose(&load("auth_missing"));
    let primary = report.primary.expect("primary diagnosis");
    assert_eq!(primary.rule_id, "auth_missing");
    assert!(primary.likely_cause.contains("Missing Authorization"));
    assert!(primary.confidence >= 0.90, "got {}", primary.confidence);
    assert!(primary.evidence.iter().any(|e| e.message.contains("401")));
}

#[test]
fn bad_json_payload_fires_with_parser_evidence() {
    let report = diagnose(&load("bad_json_payload"));
    let primary = report.primary.expect("primary diagnosis");
    assert_eq!(primary.rule_id, "bad_json_payload");
    assert!(primary
        .evidence
        .iter()
        .any(|e| e.message.contains("parse error")));
}

#[test]
fn rate_limited_uses_retry_after_header() {
    let report = diagnose(&load("rate_limited"));
    let primary = report.primary.expect("primary diagnosis");
    assert_eq!(primary.rule_id, "rate_limited");
    assert!(primary
        .evidence
        .iter()
        .any(|e| e.message.contains("Retry-After")));
    assert!(primary.confidence >= 0.90);
}

#[test]
fn webhook_signature_invalid_fires_only_signature_rule() {
    // Drift is within tolerance, so timestamp_stale must NOT fire.
    let report = diagnose(&load("webhook_signature_invalid"));
    let primary = report.primary.expect("primary");
    assert_eq!(primary.rule_id, "webhook_signature_mismatch");
    assert!(
        report.also_considered.is_empty(),
        "{:?}",
        report.also_considered
    );
    assert!(primary
        .evidence
        .iter()
        .any(|e| e.message.contains("Expected")));
}

#[test]
fn timeout_retry_observes_attempts_and_deadline() {
    let report = diagnose(&load("timeout_retry"));
    let primary = report.primary.expect("primary");
    assert_eq!(primary.rule_id, "timeout_retry");
    assert!(primary
        .evidence
        .iter()
        .any(|e| e.message.contains("client deadline")));
}

#[test]
fn config_dns_error_flags_typo_tld() {
    let report = diagnose(&load("config_dns_error"));
    let primary = report.primary.expect("primary");
    assert_eq!(primary.rule_id, "config_dns_error");
    assert!(primary
        .evidence
        .iter()
        .any(|e| e.message.contains("near-miss") || e.message.contains("TLD")));
}

// ---- arbitration: ambiguous case fires both webhook rules; signature wins ----

#[test]
fn ambiguous_webhook_ranks_signature_above_timestamp() {
    let report = diagnose(&load("webhook_signature_invalid_stale"));
    let primary = report.primary.expect("primary");
    assert_eq!(primary.rule_id, "webhook_signature_mismatch");
    assert_eq!(report.also_considered.len(), 1);
    assert_eq!(report.also_considered[0].rule_id, "webhook_timestamp_stale");
    assert!(
        primary.confidence > report.also_considered[0].confidence,
        "primary {} should outrank also_considered {}",
        primary.confidence,
        report.also_considered[0].confidence
    );
}

// ---- negatives: each rule's near-miss fixture must NOT classify ----

#[test]
fn negative_upstream_401_does_not_fire_auth_missing() {
    assert_eq!(primary_id("upstream_401"), None);
}

#[test]
fn negative_valid_json_schema_fail_does_not_fire_bad_json() {
    // Body parses; bad_json_payload must not fire. No other rule covers
    // schema mismatch, so the report should be unclassified.
    assert_eq!(primary_id("valid_json_schema_fail"), None);
}

#[test]
fn negative_non_429_does_not_fire_rate_limited() {
    assert_eq!(primary_id("non_429_high_traffic"), None);
}

#[test]
fn negative_webhook_clean_fires_neither_webhook_rule() {
    assert_eq!(primary_id("webhook_clean"), None);
}

#[test]
fn negative_single_timeout_does_not_fire_timeout_retry() {
    assert_eq!(primary_id("single_timeout_no_retry"), None);
}

#[test]
fn negative_host_match_does_not_fire_dns_error() {
    assert_eq!(primary_id("host_match"), None);
}

// ---- determinism: diagnosing the same case twice is byte-stable ----

#[test]
fn diagnose_is_deterministic() {
    let case = load("auth_missing");
    let a = diagnose(&case);
    let b = diagnose(&case);
    assert_eq!(a, b);
}

// ---- exit-code surface ----

#[test]
fn high_confidence_exits_zero() {
    let report = diagnose(&load("auth_missing"));
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn unclassified_exits_one() {
    let report = diagnose(&load("webhook_clean"));
    assert_eq!(report.exit_code(), 1);
}

// ---- silence unused-warning on helpers used only in some configs ----

#[test]
fn primary_confidence_helper_returns_zero_for_unclassified() {
    assert_eq!(primary_confidence("webhook_clean"), 0.0);
}
