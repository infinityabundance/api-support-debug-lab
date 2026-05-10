// SPDX-License-Identifier: Apache-2.0

//! Calibration-regression canary.
//!
//! A calibration test that has never failed is ceremonial. This file
//! contains the proof that the calibration framework would catch a
//! real miscalibration: it computes the same aggregate Brier score
//! as `tests/calibration.rs`, but with `idempotency_collision`'s
//! predicted confidence forced to a deliberately wrong value (0.9
//! for every case, regardless of whether the rule should fire).
//!
//! Under that corruption the Brier score must exceed the production
//! threshold of 0.05. The test asserts the failure — so the test
//! itself passes when the framework would have caught the regression.
//!
//! Gated behind the `calibration_canary` feature. Build with:
//!
//! ```bash
//! cargo test --features calibration_canary --test calibration_regression
//! ```
//!
//! Without the feature flag the file compiles to an empty test
//! module so the default `cargo test` still works.

#![cfg(feature = "calibration_canary")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use api_debug_lab::cases::Case;
use api_debug_lab::report::Diagnosis;
use api_debug_lab::rules::diagnose;

/// One labelled case loaded from disk. Identical shape to
/// `tests/calibration.rs::LabelledCase` (the two integration tests
/// are independent crates so cannot share a helper module).
struct LabelledCase {
    name: String,
    case: Case,
}

const ALL_RULES: [&str; 8] = [
    "auth_missing",
    "bad_json_payload",
    "config_dns_error",
    "idempotency_collision",
    "rate_limited",
    "timeout_retry",
    "webhook_signature_mismatch",
    "webhook_timestamp_stale",
];

/// The rule whose confidence we deliberately corrupt.
const CANARY_RULE: &str = "idempotency_collision";
/// The miscalibrated value: the canary "rule" claims this confidence
/// for every case, including ones where the rule should be silent.
/// 0.9 produces a clear miscalibration signal without being absurd.
const CANARY_CONFIDENCE: f32 = 0.9;
/// Production Brier threshold from `tests/calibration.rs`. The canary
/// test asserts the corrupted Brier exceeds this.
const PRODUCTION_BRIER_THRESHOLD: f32 = 0.05;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Walk every `case.json` under `fixtures/cases/` and return only
/// those that carry an explicit `expected_rule_id` field. Same
/// loader logic as `tests/calibration.rs` — the labels live inside
/// each case file rather than in a separate manifest.
fn load_corpus() -> Vec<LabelledCase> {
    let root = fixtures_root().join("cases");
    let mut paths: Vec<PathBuf> = Vec::new();
    walk(&root, &mut paths);
    paths.sort();
    let mut out: Vec<LabelledCase> = Vec::new();
    for path in paths {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let v: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        if !v
            .as_object()
            .is_some_and(|o| o.contains_key("expected_rule_id"))
        {
            continue;
        }
        let case = Case::load(path.to_str().unwrap(), &fixtures_root())
            .unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
        out.push(LabelledCase {
            name: case.name.clone(),
            case,
        });
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("case.json") {
            out.push(path);
        }
    }
}

fn rule_probabilities(diagnoses: &[Diagnosis]) -> BTreeMap<String, f32> {
    let mut out: BTreeMap<String, f32> = ALL_RULES.iter().map(|r| (r.to_string(), 0.0)).collect();
    for d in diagnoses {
        out.insert(d.rule_id.clone(), d.confidence);
    }
    out
}

#[test]
fn canary_proves_brier_threshold_is_load_bearing() {
    let corpus = load_corpus();
    let mut sum_sq = 0.0_f32;
    let mut n = 0usize;

    for entry in &corpus {
        let report = diagnose(&entry.case);

        let mut diagnoses: Vec<Diagnosis> = Vec::new();
        if let Some(p) = &report.primary {
            diagnoses.push(p.clone());
        }
        diagnoses.extend(report.also_considered.iter().cloned());
        let mut predicted = rule_probabilities(&diagnoses);

        // The miscalibration: pin the canary rule's predicted
        // probability at CANARY_CONFIDENCE regardless of what the
        // real rule said. This simulates a rule that has been
        // tuned far above its true accuracy.
        predicted.insert(CANARY_RULE.to_string(), CANARY_CONFIDENCE);

        for rule in &ALL_RULES {
            let predicted_p = *predicted.get(*rule).unwrap_or(&0.0);
            let ground_truth = match &entry.case.expected_rule_id {
                Some(g) if g == rule => 1.0_f32,
                _ => 0.0_f32,
            };
            let err = predicted_p - ground_truth;
            sum_sq += err * err;
            n += 1;
        }
    }
    // Touch `name` so it does not flag unused under `#[cfg(feature = ...)]`.
    let _ = corpus.first().map(|c| c.name.as_str());

    let brier = sum_sq / n as f32;
    assert!(
        brier > PRODUCTION_BRIER_THRESHOLD,
        "canary failed: simulated miscalibration produced Brier {:.4}, \
         which is *not* above the production threshold {:.4}. \
         Either the calibration framework no longer catches this class \
         of regression, or the canary's CANARY_CONFIDENCE / \
         CANARY_RULE was changed to a value that is no longer \
         miscalibrated. Investigate before merging.",
        brier,
        PRODUCTION_BRIER_THRESHOLD
    );
}
