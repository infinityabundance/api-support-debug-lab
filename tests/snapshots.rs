// SPDX-License-Identifier: Apache-2.0

//! Snapshot tests pinning byte-stable report output.
//!
//! For every bundled positive fixture, two snapshots: one of the
//! human-readable rendering and one of the pretty-printed JSON.
//! Stored under `tests/snapshots/` and reviewed via
//! `cargo install cargo-insta && cargo insta review`. Snapshot diffs
//! in PRs become legible because the formatter is byte-stable
//! (BTreeMap iteration, no clock, no path leakage).
//!
//! These tests catch any change to:
//!
//! - rule confidence values (visible in `CONFIDENCE: 0.92`),
//! - evidence message wording (the bullet list under `EVIDENCE:`),
//! - reproduction shape (header order, body escaping, `--data-raw`),
//! - the structural skeleton of either format.
//!
//! When you intentionally change rule output, run the test, accept
//! the new snapshot, and commit the snapshot file in the same
//! change. Do not silently drop snapshot updates from a PR.

use std::path::PathBuf;

use api_debug_lab::cases::Case;
use api_debug_lab::report::Format;
use api_debug_lab::rules::diagnose;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn report_for(name: &str) -> api_debug_lab::report::Report {
    let case = Case::load(name, &fixtures_root()).expect("load fixture");
    diagnose(&case)
}

macro_rules! snap_case {
    ($name:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn human() {
                let r = report_for(stringify!($name));
                insta::assert_snapshot!(r.render(Format::Human));
            }

            #[test]
            fn json() {
                let r = report_for(stringify!($name));
                insta::assert_snapshot!(r.render(Format::Json));
            }
        }
    };
}

snap_case!(auth_missing);
snap_case!(bad_json_payload);
snap_case!(rate_limited);
snap_case!(webhook_signature_invalid);
snap_case!(webhook_signature_invalid_stale);
snap_case!(timeout_retry);
snap_case!(config_dns_error);
