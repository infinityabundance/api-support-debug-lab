// SPDX-License-Identifier: Apache-2.0

//! Schema-validation regression test.
//!
//! Walks every directory under `fixtures/cases/` (including
//! `_negatives/`), loads each `case.json`, and asserts it satisfies
//! the JSON Schema Draft 2020-12 document at
//! `fixtures/cases.schema.json`. The schema and the on-disk fixtures
//! are two independent representations of the same contract — this
//! test is what keeps them from drifting.
//!
//! Adding a new field on the [`api_debug_lab::cases::Case`] struct is
//! a three-step process: (1) update the struct, (2) update the
//! schema's `$defs` to match, (3) extend any fixture that needs the
//! new shape. This test fires if step 2 is forgotten.

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::JSONSchema;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn collect_case_jsons(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_case_jsons(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("case.json") {
            out.push(path);
        }
    }
}

#[test]
fn every_case_json_validates_against_schema() {
    let root = fixtures_root();
    let schema_text =
        fs::read_to_string(root.join("cases.schema.json")).expect("read cases.schema.json");
    let schema_json: serde_json::Value = serde_json::from_str(&schema_text).expect("parse schema");
    let compiled = JSONSchema::compile(&schema_json).expect("compile schema");

    let mut cases: Vec<PathBuf> = Vec::new();
    collect_case_jsons(&root.join("cases"), &mut cases);
    assert!(
        cases.len() >= 30,
        "expected at least 30 fixtures, got {}",
        cases.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for path in &cases {
        let raw = fs::read_to_string(path).expect("read case.json");
        let json: serde_json::Value = serde_json::from_str(&raw).expect("parse case.json");
        let messages: Vec<String> = match compiled.validate(&json) {
            Ok(()) => Vec::new(),
            Err(errors) => errors
                .map(|err| format!("{}: {err}", path.display()))
                .collect(),
        };
        failures.extend(messages);
    }
    assert!(
        failures.is_empty(),
        "schema violations:\n{}",
        failures.join("\n")
    );
}
