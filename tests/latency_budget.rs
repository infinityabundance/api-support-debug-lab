// SPDX-License-Identifier: Apache-2.0

//! Per-rule latency-budget regression test.
//!
//! Asserts that the median wall-clock time spent inside each rule's
//! `evaluate` is below a generous budget (100 µs per rule per case).
//! Pairs with `benches/diagnose.rs` — the bench produces the actual
//! numbers, this test asserts the budget would catch a regression.
//!
//! Current bench medians are ~2–4 µs end-to-end; the per-rule budget
//! has plenty of headroom. The point of the test is to fail loudly
//! the day a future rule accidentally introduces an O(n²) loop, a
//! synchronous I/O call, or a heavy regex.
//!
//! Single-threaded; deterministic; no system clock outside `Instant`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use api_debug_lab::cases::Case;
use api_debug_lab::rules::diagnose_traced;

const ITERATIONS: usize = 200;
const BUDGET: Duration = Duration::from_micros(100);
const FIXTURES: &[&str] = &[
    "auth_missing",
    "bad_json_payload",
    "rate_limited",
    "webhook_signature_invalid",
    "webhook_signature_invalid_stale",
    "webhook_stripe_v1",
    "webhook_slack_v0",
    "webhook_github_hmac",
    "timeout_retry",
    "timeout_retry_jsonl",
    "timeout_retry_partial_outage",
    "timeout_retry_midnight_rollover",
    "config_dns_error",
    "idempotency_collision",
];

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

#[test]
fn per_rule_median_within_budget() {
    let cases: Vec<(String, Case)> = FIXTURES
        .iter()
        .map(|n| {
            let case = Case::load(n, &fixtures_root()).unwrap_or_else(|e| panic!("load {n}: {e}"));
            (n.to_string(), case)
        })
        .collect();

    // For each (case, rule) pair, collect ITERATIONS durations and
    // assert the median is below BUDGET. Median (not mean) defends
    // against a noisy first-iteration warm-up.
    let mut violations: Vec<String> = Vec::new();
    for (name, case) in &cases {
        let mut samples: BTreeMap<String, Vec<Duration>> = BTreeMap::new();
        for _ in 0..ITERATIONS {
            let (_report, traces) = diagnose_traced(case);
            for t in traces {
                samples.entry(t.rule_id).or_default().push(t.duration);
            }
        }
        for (rule_id, mut durs) in samples {
            durs.sort();
            let median = durs[durs.len() / 2];
            if median > BUDGET {
                violations.push(format!(
                    "case {} rule {}: median {:?} > budget {:?}",
                    name, rule_id, median, BUDGET
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "latency-budget violations:\n{}",
        violations.join("\n")
    );
}
