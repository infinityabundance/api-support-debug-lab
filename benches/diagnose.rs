// SPDX-License-Identifier: Apache-2.0

//! Criterion benchmark for `diagnose` over every bundled positive
//! fixture.
//!
//! Provides the baseline numbers in `docs/benchmarks.md`. The
//! benchmark is a sanity check, not a load test — its purpose is to
//! make per-case latency visible in the diff so a future change that
//! adds a heavy dependency or accidentally allocates hotly will be
//! impossible to merge silently.
//!
//! Run with:
//!
//! ```bash
//! cargo bench --bench diagnose            # full criterion run
//! cargo bench --bench diagnose -- --quick # ~10 iterations per case
//! ```
//!
//! The `--quick` form is what `docs/benchmarks.md` was captured from.
//! Differences between the two are within ~5 % on the same hardware.

use std::path::PathBuf;

use api_debug_lab::cases::Case;
use api_debug_lab::rules::diagnose;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn bench_diagnose(c: &mut Criterion) {
    let names = [
        "auth_missing",
        "bad_json_payload",
        "rate_limited",
        "webhook_signature_invalid",
        "webhook_signature_invalid_stale",
        "timeout_retry",
        "config_dns_error",
    ];
    let cases: Vec<(String, Case)> = names
        .iter()
        .map(|n| {
            let case = Case::load(n, &fixtures_root()).expect("load fixture");
            (n.to_string(), case)
        })
        .collect();

    let mut group = c.benchmark_group("diagnose");
    for (name, case) in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), case, |b, case| {
            b.iter(|| {
                let report = diagnose(black_box(case));
                // black_box prevents the optimiser from eliding the
                // call; the assignment consumes the #[must_use] Report.
                let _ = black_box(report);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_diagnose);
criterion_main!(benches);
