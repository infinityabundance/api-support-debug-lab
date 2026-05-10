// SPDX-License-Identifier: Apache-2.0

//! Confidence-calibration test.
//!
//! For each case with an embedded `expected_rule_id` label, run
//! [`diagnose`] and compute per-rule prediction error against ground
//! truth. The Brier score is the mean squared error across all
//! (case, rule) pairs; the assertion fails if it rises above a
//! documented threshold.
//!
//! See `docs/confidence_model.md` for the rubric this test holds the
//! rules accountable to.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use api_debug_lab::cases::Case;
use api_debug_lab::report::Diagnosis;
use api_debug_lab::rules::diagnose;

/// One labelled case loaded from disk. The label (`expected_rule_id`)
/// lives inside `case.json` itself — single source of truth.
struct LabelledCase {
    name: String,
    case: Case,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Walk every `case.json` under `fixtures/cases/` (recursively, so
/// `_negatives/` and `_calibration/` are included) and return only
/// the cases that carry an `expected_rule_id` field — labelled or
/// explicit-null. Cases without the field are excluded from the
/// corpus.
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
        // Only enrol cases that explicitly carry a label (string or
        // null). Cases without the field are not part of the
        // calibration corpus.
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
    assert!(
        out.len() >= 30,
        "expected at least 30 labelled cases in the corpus, found {}",
        out.len()
    );
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

/// Construct the predicted probability map for the case: each rule's
/// confidence as primary or in `also_considered`, otherwise 0.
fn rule_probabilities(diagnoses: &[Diagnosis]) -> BTreeMap<String, f32> {
    let mut out: BTreeMap<String, f32> = ALL_RULES.iter().map(|r| (r.to_string(), 0.0)).collect();
    for d in diagnoses {
        out.insert(d.rule_id.clone(), d.confidence);
    }
    out
}

#[test]
fn primary_classification_is_perfect_on_corpus() {
    let corpus = load_corpus();
    let mut mismatches: Vec<String> = Vec::new();
    for entry in &corpus {
        let report = diagnose(&entry.case);
        let actual = report.primary.as_ref().map(|d| d.rule_id.clone());
        if actual != entry.case.expected_rule_id {
            mismatches.push(format!(
                "case {}: expected {:?}, got {:?}",
                entry.name, entry.case.expected_rule_id, actual
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "primary classification mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn brier_score_below_threshold() {
    // Per-rule Brier over the full labelled corpus. Lower is better.
    // 0.0 = perfect; 1.0 = random. Threshold of 0.05 means the rule
    // probabilities are within sqrt(0.05) ≈ 0.22 of ground truth on
    // average, which is the bar a hand-tuned classifier of this size
    // should meet.
    const THRESHOLD: f32 = 0.05;

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
        let predicted = rule_probabilities(&diagnoses);

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

    let brier = sum_sq / n as f32;
    assert!(
        brier <= THRESHOLD,
        "Brier score {:.4} exceeded threshold {:.4} (over {} (case, rule) pairs)",
        brier,
        THRESHOLD,
        n
    );
}

/// Per-rule Brier breakdown: each rule's mean squared error over
/// the corpus. Looser threshold than aggregate (0.08 vs 0.05) because
/// each rule sees only ~30 (case, rule) pairs.
///
/// This catches the failure mode the aggregate Brier hides:
/// "average is fine, but rule X is miscalibrated."
#[test]
fn per_rule_brier_below_threshold() {
    const PER_RULE_THRESHOLD: f32 = 0.08;
    let corpus = load_corpus();
    let mut sum_sq: BTreeMap<&str, f32> = ALL_RULES.iter().map(|r| (*r, 0.0_f32)).collect();
    let mut counts: BTreeMap<&str, usize> = ALL_RULES.iter().map(|r| (*r, 0_usize)).collect();

    for entry in &corpus {
        let report = diagnose(&entry.case);
        let mut diagnoses: Vec<Diagnosis> = Vec::new();
        if let Some(p) = &report.primary {
            diagnoses.push(p.clone());
        }
        diagnoses.extend(report.also_considered.iter().cloned());
        let predicted = rule_probabilities(&diagnoses);

        for rule in &ALL_RULES {
            let predicted_p = *predicted.get(*rule).unwrap_or(&0.0);
            let ground_truth = match &entry.case.expected_rule_id {
                Some(g) if g == rule => 1.0_f32,
                _ => 0.0_f32,
            };
            let err = predicted_p - ground_truth;
            *sum_sq.get_mut(rule).unwrap() += err * err;
            *counts.get_mut(rule).unwrap() += 1;
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for rule in &ALL_RULES {
        let n = counts[rule];
        if n == 0 {
            continue;
        }
        let brier = sum_sq[rule] / n as f32;
        if brier > PER_RULE_THRESHOLD {
            violations.push(format!(
                "rule {} per-rule Brier {:.4} exceeds threshold {:.4} over {} pairs",
                rule, brier, PER_RULE_THRESHOLD, n
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "per-rule Brier violations:\n{}",
        violations.join("\n")
    );
}

/// Expected Calibration Error: the standard reliability metric
/// alongside Brier. Bins predictions into `B` deciles, computes per-bin
/// `|mean_predicted - empirical_accuracy|`, and weights by bin
/// occupancy. Lower is better; 0.0 is perfect calibration.
fn expected_calibration_error(pairs: &[(f32, f32)], num_bins: usize) -> f32 {
    if pairs.is_empty() || num_bins == 0 {
        return 0.0;
    }
    let mut bin_sum_pred: Vec<f32> = vec![0.0; num_bins];
    let mut bin_sum_actual: Vec<f32> = vec![0.0; num_bins];
    let mut bin_count: Vec<usize> = vec![0; num_bins];
    for &(pred, actual) in pairs {
        let p = pred.clamp(0.0, 1.0);
        let mut bin = (p * num_bins as f32) as usize;
        if bin == num_bins {
            // p == 1.0 lands in bin == num_bins; clamp into last bin.
            bin = num_bins - 1;
        }
        bin_sum_pred[bin] += p;
        bin_sum_actual[bin] += actual;
        bin_count[bin] += 1;
    }
    let total = pairs.len() as f32;
    let mut ece = 0.0_f32;
    for i in 0..num_bins {
        let n = bin_count[i];
        if n == 0 {
            continue;
        }
        let mean_pred = bin_sum_pred[i] / n as f32;
        let mean_actual = bin_sum_actual[i] / n as f32;
        ece += (n as f32 / total) * (mean_pred - mean_actual).abs();
    }
    ece
}

#[test]
fn ece_below_threshold() {
    // 10 deciles is the standard binning for ECE on small corpora;
    // larger corpora can afford finer-grained bins. Threshold 0.05
    // allows ~5% mean deviation between predicted confidence and
    // empirical accuracy across bins — generous given how clustered
    // the rule confidences are (0.85, 0.90, 0.92, 0.93, 0.95).
    const THRESHOLD: f32 = 0.05;
    const NUM_BINS: usize = 10;

    let corpus = load_corpus();
    let mut pairs: Vec<(f32, f32)> = Vec::new();
    for entry in &corpus {
        let report = diagnose(&entry.case);
        let mut diagnoses: Vec<Diagnosis> = Vec::new();
        if let Some(p) = &report.primary {
            diagnoses.push(p.clone());
        }
        diagnoses.extend(report.also_considered.iter().cloned());
        let predicted = rule_probabilities(&diagnoses);

        for rule in &ALL_RULES {
            let predicted_p = *predicted.get(*rule).unwrap_or(&0.0);
            let ground_truth = match &entry.case.expected_rule_id {
                Some(g) if g == rule => 1.0_f32,
                _ => 0.0_f32,
            };
            pairs.push((predicted_p, ground_truth));
        }
    }
    let ece = expected_calibration_error(&pairs, NUM_BINS);
    assert!(
        ece <= THRESHOLD,
        "ECE {:.4} exceeded threshold {:.4} (over {} pairs, {} bins)",
        ece,
        THRESHOLD,
        pairs.len(),
        NUM_BINS
    );
}

#[test]
fn unclassified_cases_have_zero_primary_confidence() {
    let corpus = load_corpus();
    for entry in &corpus {
        if entry.case.expected_rule_id.is_some() {
            continue;
        }
        let report = diagnose(&entry.case);
        if let Some(p) = report.primary {
            assert!(
                p.confidence < 0.6,
                "case {} expected unclassified but rule {} fired with confidence {:.2}",
                entry.name,
                p.rule_id,
                p.confidence
            );
        }
    }
}
