// SPDX-License-Identifier: Apache-2.0

//! # API Support Debug Lab — diagnostic library
//!
//! This library is the engine behind the `api-debug-lab` CLI. It loads a
//! [`Case`] from a fixture directory or a `case.json` path, runs a fixed
//! set of rules over it, and returns a [`Report`] that ranks the firing
//! diagnoses by confidence.
//!
//! ## How the pieces fit together
//!
//! ```text
//! fixtures/cases/<name>/case.json    →  Case (serde, schema-validated)
//! fixtures/cases/<name>/server.log   →  &str (lazy load via Case::load_log)
//! fixtures/cases/<name>/secret.txt   →  Vec<u8> (via Case::load_secret)
//!     │
//!     ▼
//! all_rules() : Vec<Box<dyn Rule>>
//!     │
//!     ▼   one Rule::evaluate per rule, all measured by diagnose_traced
//! Diagnosis[]  ─ sorted by confidence desc, alphabetical tiebreak ─►  Report
//! ```
//!
//! ## Determinism
//!
//! Every code path here is deterministic. Headers iterate via
//! [`std::collections::BTreeMap`], reproductions inline the body so
//! output paths never bake in machine-specific filesystem state, no
//! system clock or RNG is consulted. The byte-stable contract is held
//! to via snapshot tests in `tests/snapshots.rs`.
//!
//! ## No I/O beyond local files
//!
//! No network calls. No environment variables. No global state. The
//! library is pure with respect to the inputs you hand it; the CLI
//! does its own filesystem reads via [`Case::load`].
//!
//! ## Public surface
//!
//! Most callers will use the re-exports below: load a case with
//! [`Case::load`], call [`diagnose`] or [`diagnose_traced`], and render
//! the resulting [`Report`] through [`Report::render`].
//!
//! ```ignore
//! use api_debug_lab::{Case, diagnose, Format};
//! use std::path::Path;
//!
//! let case = Case::load("auth_missing", Path::new("fixtures")).unwrap();
//! let report = diagnose(&case);
//! print!("{}", report.render(Format::Human));
//! std::process::exit(report.exit_code());
//! ```

#![deny(missing_docs)]

pub mod cases;
mod embedded;
pub mod evidence;
pub mod report;
pub mod rules;

pub use cases::{Case, CaseLoadError, Severity};
pub use evidence::{Evidence, Pointer};
pub use report::{Diagnosis, Format, Report};
pub use rules::{all_rules, diagnose, diagnose_traced, Rule, RuleTrace};
