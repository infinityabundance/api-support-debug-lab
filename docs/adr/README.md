# Architecture Decision Records

Lightweight records of the design decisions whose *why* is not
visible from the code alone. Format follows the
[MADR](https://adr.github.io/madr/) template — Context, Decision,
Consequences. Each record is short (≤ 60 lines) and dated.

| #    | Title                                                       | Status   |
| ---- | ----------------------------------------------------------- | -------- |
| [0001](0001-rule-based-not-learned.md) | Rule-based classification, not machine-learned | Accepted |
| [0002](0002-per-line-json-autodetect.md) | Per-line JSON-or-text log auto-detection      | Accepted |
| [0003](0003-static-rule-slice.md) | Static `&[&dyn Rule]` slice, not `Vec<Box<dyn>>` | Accepted |

## When to add an ADR

Add a record when a design choice is non-obvious from reading the
code, was contested at the time, has tradeoffs the next maintainer
should know about, or constrains future work. Skip records for
trivial decisions (variable names, file layout) and for decisions
already explained by an inline `// Why:` comment.
