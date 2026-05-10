# Code coverage

A measured number, not a vibe. Produced by `cargo llvm-cov` over the
full test suite (default features; calibration canary excluded
because it is a regression-against-itself test, not a coverage test).

## How to reproduce

```bash
cargo install --locked cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --summary-only
```

A full HTML report is available via `cargo llvm-cov --html`. The text
summary below is what gets committed; the HTML is regenerated on
demand.

## Snapshot

- **Date**: 2026-05-10
- **rustc**: 1.94.1 (e408947bf 2026-03-25)
- **Total regions**: 1889 (144 missed → **92.4 %** covered)
- **Total functions**: 108 (9 missed → **91.7 %** covered)
- **Total lines**: 1199 (84 missed → **93.0 %** covered)

### Per-file

| File           | Regions covered | Functions covered | Lines covered |
| -------------- | --------------- | ----------------- | ------------- |
| `cases.rs`     | 88.2 %          | 85.7 %            | 86.4 %        |
| `evidence.rs`  | 75.0 %          | 66.7 %            | 75.0 %        |
| `main.rs`      | 78.9 %          | 73.3 %            | 81.0 %        |
| `report.rs`    | 99.1 %          | 80.0 %            | 98.7 %        |
| `rules.rs`     | 95.5 %          | 98.6 %            | 96.5 %        |
| **Total**      | **92.4 %**      | **91.7 %**        | **93.0 %**    |

## Where the gaps are

- `evidence.rs` and `main.rs` carry the lowest coverage, both around
  three-quarters. For `evidence.rs` this is partly because the
  `Pointer` struct is exercised entirely through `Evidence`'s
  constructors; for `main.rs` the gap is the error paths
  (`anyhow::bail!` branches that the tests do not deliberately
  trigger).
- `report.rs` covers the human renderer thoroughly (99 %) but not the
  `Default` derives that are never invoked in tests.
- `rules.rs` covers the rule logic at ~96 %. The remaining gap is
  inside the `LogLine` JSON-typed-value match arms that the bundled
  fixtures do not all exercise (same gap surfaced by the mutation
  report; see `docs/mutation_report.md`).

## Honest framing

92 % regions / 93 % lines is the bar for a hand-written rule
classifier of this size. Pushing past 95 % requires:

- Adversarial fixtures that exercise the `LogLine::field` match arms
  for `Number` and `Bool` values.
- Synthetic invocations of the error paths in `src/main.rs` (e.g., a
  unit test that calls `run_corpus` against a deliberately-empty
  directory).
- Removing dead `Default` impls that are derived for serde but never
  constructed at runtime.

These are not blockers and are not scheduled. The number above is
what we have, measured, on the date stamped at the top of this file.
