// SPDX-License-Identifier: Apache-2.0

//! End-to-end CLI tests via `assert_cmd`.
//!
//! Each test runs the actual built binary against the bundled fixtures and
//! checks exit code + stdout. CWD is pinned to `CARGO_MANIFEST_DIR` so the
//! default `./fixtures` lookup resolves regardless of where the test runner
//! invoked us.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    cmd_in(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn cmd_in(cwd: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("api-debug-lab").expect("binary built");
    c.current_dir(cwd);
    c
}

#[test]
fn list_cases_lists_fourteen_positive_fixtures() {
    cmd()
        .arg("list-cases")
        .assert()
        .success()
        .stdout(predicate::str::contains("auth_missing"))
        .stdout(predicate::str::contains("bad_json_payload"))
        .stdout(predicate::str::contains("idempotency_collision"))
        .stdout(predicate::str::contains("rate_limited"))
        .stdout(predicate::str::contains("timeout_retry_jsonl"))
        .stdout(predicate::str::contains("timeout_retry_midnight_rollover"))
        .stdout(predicate::str::contains("timeout_retry_partial_outage"))
        .stdout(predicate::str::contains("webhook_github_hmac"))
        .stdout(predicate::str::contains("webhook_signature_invalid"))
        .stdout(predicate::str::contains("webhook_signature_invalid_stale"))
        .stdout(predicate::str::contains("webhook_slack_v0"))
        .stdout(predicate::str::contains("webhook_stripe_v1"))
        .stdout(predicate::str::contains("timeout_retry"))
        .stdout(predicate::str::contains("config_dns_error"));
}

#[test]
fn list_cases_does_not_leak_negatives() {
    cmd()
        .arg("list-cases")
        .assert()
        .success()
        .stdout(predicate::str::contains("upstream_401").not())
        .stdout(predicate::str::contains("webhook_clean").not());
}

#[test]
fn installed_mode_lists_embedded_fixtures_without_repo_checkout() {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    cmd_in(tmp.path())
        .arg("list-cases")
        .assert()
        .success()
        .stdout(predicate::str::contains("auth_missing"))
        .stdout(predicate::str::contains("webhook_stripe_v1"))
        .stdout(predicate::str::contains("webhook_clean").not());
}

#[test]
fn installed_mode_diagnoses_embedded_fixture_with_secret() {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    cmd_in(tmp.path())
        .args(["diagnose", "webhook_signature_invalid"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Webhook signature does not match recomputed HMAC",
        ));
}

#[test]
fn installed_mode_can_load_embedded_negative_fixture() {
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    cmd_in(tmp.path())
        .args(["diagnose", "webhook_clean"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("unclassified"));
}

#[test]
fn diagnose_auth_missing_succeeds() {
    cmd()
        .args(["diagnose", "auth_missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Missing Authorization header"))
        .stdout(predicate::str::contains("CONFIDENCE: 0.95"));
}

#[test]
fn diagnose_unknown_case_exits_two() {
    cmd().args(["diagnose", "no_such_case"]).assert().code(2);
}

#[test]
fn diagnose_unclassified_exits_one() {
    cmd()
        .args(["diagnose", "webhook_clean"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("unclassified"));
}

#[test]
fn diagnose_json_format_is_valid_json() {
    let output = cmd()
        .args([
            "diagnose",
            "webhook_signature_invalid_stale",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&output).expect("stdout is valid JSON");
    assert_eq!(parsed["primary"]["rule_id"], "webhook_signature_mismatch");
}

#[test]
fn diagnose_is_byte_stable_across_runs() {
    let a = cmd()
        .args(["diagnose", "rate_limited"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let b = cmd()
        .args(["diagnose", "rate_limited"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(a, b, "non-deterministic diagnose output");
}

#[test]
fn explain_names_rule_and_evidence_pointers() {
    cmd()
        .args(["explain", "webhook_signature_invalid"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rule webhook_signature_mismatch"))
        .stdout(predicate::str::contains("[request.headers.x-signature]"));
}

#[test]
fn replay_emits_curl_then_diagnosis() {
    cmd()
        .args(["replay", "auth_missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("curl -X POST"))
        .stdout(predicate::str::contains("CASE: auth_missing"));
}

#[test]
fn corpus_summary_reports_classified_and_unclassified_counts() {
    let mut c = cmd();
    c.args(["corpus", "fixtures/cases"]);
    let out = c.assert().code(1).get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("Summary:"), "no summary line in:\n{s}");
    assert!(s.contains("classified"), "no classified count in summary");
    assert!(s.contains("Per-rule fire counts:"), "no per-rule breakdown");
    assert!(
        s.contains("auth_missing"),
        "expected auth_missing in counts"
    );
}

#[test]
fn corpus_ndjson_emits_one_object_per_line() {
    let mut c = cmd();
    c.args(["corpus", "fixtures/cases", "--ndjson"]);
    let out = c.assert().code(1).get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 14,
        "expected >=14 ndjson lines, got {}",
        lines.len()
    );
    for line in &lines {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("non-JSON ndjson line: {line}"));
    }
}

#[test]
fn corpus_on_only_positives_exits_zero() {
    use std::fs;
    use tempfile::TempDir;
    let tmp = TempDir::new().expect("tmpdir");
    // Copy one positive fixture into the tmpdir.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/cases/auth_missing");
    let dst = tmp.path().join("auth_missing");
    fs::create_dir_all(&dst).unwrap();
    for entry in fs::read_dir(&src).unwrap().flatten() {
        let n = entry.file_name();
        fs::copy(entry.path(), dst.join(&n)).unwrap();
    }
    cmd().args(["corpus"]).arg(tmp.path()).assert().success();
}

#[test]
fn report_alias_matches_human_diagnose() {
    let report_out = cmd()
        .args(["report", "auth_missing"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let diag_out = cmd()
        .args(["diagnose", "auth_missing"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(report_out, diag_out);
}
