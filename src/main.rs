// SPDX-License-Identifier: Apache-2.0

//! Thin CLI wrapper over the `api_debug_lab` library.
//!
//! Each subcommand is a function in this file; they share a `Cli`
//! struct parsed via `clap` derive. The CLI does no rule logic — it
//! loads cases, hands them to `diagnose` / `diagnose_traced`, and
//! formats the result. Process-level concerns (exit codes, stderr
//! tracing, directory walking for `corpus`) live here.
//!
//! ## Exit code convention
//!
//! - `0` — primary diagnosis fired with confidence ≥ 0.60.
//! - `1` — case unclassified or low-confidence (also: corpus had ≥ 1
//!   unclassified or ≥ 1 load error).
//! - `2` — bad input: unknown case name, unreadable file, parse error.
//!
//! These are documented in [README.md](../README.md) and tested in
//! `tests/diagnose_cli.rs`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use api_debug_lab::cases::{list_cases, Case};
use api_debug_lab::report::Format;
use api_debug_lab::rules::{all_rules, diagnose};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "api-debug-lab",
    version,
    about = "Reproducible API troubleshooting fixtures and a Rust diagnostic CLI."
)]
struct Cli {
    /// Override the fixtures root (defaults to ./fixtures).
    #[arg(long, value_name = "DIR", global = true)]
    fixtures: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the bundled case fixtures.
    ListCases,
    /// Diagnose a case by name (e.g. `auth_missing`) or path to a case.json / fixture dir.
    Diagnose {
        case: String,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
        /// Print per-rule evaluation timing and outcome to stderr.
        #[arg(long)]
        trace: bool,
    },
    /// Print which rules fired and the source pointer for each evidence item.
    Explain { case: String },
    /// Print the curl reproduction command followed by the diagnosis (offline).
    Replay { case: String },
    /// Full report including escalation note (same as `diagnose` in human format).
    Report { case: String },
    /// Sweep a directory of `case.json` files (recursively) and emit a summary.
    Corpus {
        /// Directory to sweep. Any `case.json` under this path will be diagnosed.
        dir: PathBuf,
        /// Emit one JSON object per line instead of the default human summary.
        #[arg(long)]
        ndjson: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let fixtures = cli
        .fixtures
        .clone()
        .unwrap_or_else(|| PathBuf::from("fixtures"));

    let result = match cli.cmd {
        Cmd::ListCases => run_list(&fixtures),
        Cmd::Diagnose {
            case,
            format,
            trace,
        } => run_diagnose(&case, &fixtures, format, trace),
        Cmd::Explain { case } => run_explain(&case, &fixtures),
        Cmd::Replay { case } => run_replay(&case, &fixtures),
        Cmd::Report { case } => run_diagnose(&case, &fixtures, Format::Human, false),
        Cmd::Corpus { dir, ndjson } => run_corpus(&dir, ndjson),
    };

    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

/// Print one positive fixture name per line.
///
/// `_negatives/` and other underscore-prefixed sets are excluded by
/// [`list_cases`]. The CLI's `corpus` subcommand is the way to scan
/// all fixtures including negatives.
fn run_list(fixtures: &Path) -> Result<i32> {
    let names = list_cases(fixtures);
    if names.is_empty() {
        anyhow::bail!(
            "no fixtures found under {} (run from repo root or pass --fixtures)",
            fixtures.display()
        );
    }
    for name in names {
        println!("{name}");
    }
    Ok(0)
}

/// Diagnose one case and write the report to stdout in the chosen
/// format.
///
/// When `trace` is true, per-rule wall-clock timing and outcome go
/// to stderr (so they don't pollute stdout, which is byte-stable
/// for snapshot tests). Returns the report's process-level exit
/// code; the caller maps it to an `ExitCode`.
fn run_diagnose(case_name: &str, fixtures: &Path, format: Format, trace: bool) -> Result<i32> {
    use api_debug_lab::rules::diagnose_traced;
    let case =
        Case::load(case_name, fixtures).with_context(|| format!("loading case {case_name}"))?;
    if trace {
        let (report, traces) = diagnose_traced(&case);
        eprintln!("# trace: per-rule wall-clock timing");
        let total_ns: u128 = traces.iter().map(|t| t.duration.as_nanos()).sum();
        for t in &traces {
            let outcome = match t.confidence {
                Some(c) => format!("fired (confidence {:.2})", c),
                None => "skipped".to_string(),
            };
            eprintln!(
                "{:<32} {:>9.2} µs  {}",
                t.rule_id,
                t.duration.as_secs_f64() * 1e6,
                outcome
            );
        }
        eprintln!("{:<32} {:>9.2} µs  total", "", total_ns as f64 / 1000.0);
        print!("{}", report.render(format));
        Ok(report.exit_code())
    } else {
        let report = diagnose(&case);
        print!("{}", report.render(format));
        Ok(report.exit_code())
    }
}

/// Print every rule that fires on the case, with its confidence and
/// the source pointer for each evidence item. Useful for auditing a
/// diagnosis or for understanding why a rule did *not* fire as the
/// primary (its confidence shown next to the others). Exits 1 if no
/// rule fires at all.
fn run_explain(case_name: &str, fixtures: &Path) -> Result<i32> {
    let case =
        Case::load(case_name, fixtures).with_context(|| format!("loading case {case_name}"))?;
    let mut fired = false;
    for rule in all_rules() {
        // `rule` is `&&dyn Rule` (slice element); auto-deref handles it.
        if let Some(diag) = rule.evaluate(&case) {
            fired = true;
            println!(
                "rule {} fired with confidence {:.2}",
                rule.id(),
                diag.confidence
            );
            for ev in &diag.evidence {
                match &ev.pointer {
                    Some(p) => match p.line {
                        Some(line) => {
                            println!("  - [{}:{line}] {}", p.source, ev.message);
                        }
                        None => println!("  - [{}] {}", p.source, ev.message),
                    },
                    None => println!("  - {}", ev.message),
                }
            }
        }
    }
    if !fired {
        println!("no rule fired for case {case_name}");
        return Ok(1);
    }
    Ok(0)
}

/// Print the deterministic curl reproduction first, then the human
/// report. Offline by design — the curl is for the reviewer to run
/// by hand against a real service if they want.
fn run_replay(case_name: &str, fixtures: &Path) -> Result<i32> {
    let case =
        Case::load(case_name, fixtures).with_context(|| format!("loading case {case_name}"))?;
    let report = diagnose(&case);
    println!("# Reproduction (offline; copy/paste to run against a real service)");
    println!("{}", report.reproduction);
    println!();
    print!("{}", report.render(Format::Human));
    Ok(report.exit_code())
}

/// Walk `dir` recursively and return every `case.json` path found,
/// sorted alphabetically for deterministic output.
fn collect_case_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// Recursive helper for [`collect_case_files`]. Pushes any
/// `case.json` it finds into `out`; descends into subdirectories.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.file_name().and_then(|s| s.to_str()) == Some("case.json") {
            out.push(path);
        }
    }
    Ok(())
}

/// Diagnose every `case.json` in `dir` and emit a per-case line plus
/// a summary of total / classified / unclassified / load-error counts
/// and a per-rule fire breakdown.
///
/// `ndjson` switches output to one JSON object per line, suitable for
/// piping into `jq` or downstream tooling. The exit code is `0` only
/// if every case classified above threshold and no load errors
/// occurred — otherwise `1`. This is what makes `corpus` usable as a
/// regression check: bolt it onto a directory of customer-supplied
/// captures and exit-code-fail when something newly does not classify.
fn run_corpus(dir: &Path, ndjson: bool) -> Result<i32> {
    let case_files = collect_case_files(dir)?;
    if case_files.is_empty() {
        anyhow::bail!("no case.json files found under {}", dir.display());
    }

    let mut classified = 0usize;
    let mut unclassified = 0usize;
    let mut load_errors = 0usize;
    let mut by_rule: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    for path in &case_files {
        let case = match Case::load(path.to_str().unwrap_or_default(), dir) {
            Ok(c) => c,
            Err(e) => {
                load_errors += 1;
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"path": path.to_string_lossy(), "error": e.to_string()})
                    );
                } else {
                    println!("{}: load error: {e}", path.display());
                }
                continue;
            }
        };
        let report = diagnose(&case);
        let rel = path.strip_prefix(dir).unwrap_or(path);
        match &report.primary {
            Some(d) if d.confidence >= 0.6 => {
                classified += 1;
                *by_rule.entry(d.rule_id.clone()).or_insert(0) += 1;
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": rel.to_string_lossy(),
                            "case": case.name,
                            "rule_id": d.rule_id,
                            "confidence": d.confidence,
                            "primary_likely_cause": d.likely_cause,
                            "also_considered": report.also_considered.len(),
                        })
                    );
                } else {
                    println!(
                        "{:<60} {:<28} confidence {:.2}",
                        rel.display(),
                        d.rule_id,
                        d.confidence
                    );
                }
            }
            _ => {
                unclassified += 1;
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": rel.to_string_lossy(),
                            "case": case.name,
                            "rule_id": null,
                            "confidence": 0.0,
                        })
                    );
                } else {
                    println!(
                        "{:<60} {:<28} confidence 0.00",
                        rel.display(),
                        "<unclassified>"
                    );
                }
            }
        }
    }

    if !ndjson {
        println!();
        println!(
            "Summary: {} case(s); {} classified, {} unclassified, {} load errors",
            case_files.len(),
            classified,
            unclassified,
            load_errors
        );
        if !by_rule.is_empty() {
            println!("Per-rule fire counts:");
            for (rule, count) in &by_rule {
                println!("  {rule:<32} {count}");
            }
        }
    }

    if unclassified == 0 && load_errors == 0 {
        Ok(0)
    } else {
        Ok(1)
    }
}
