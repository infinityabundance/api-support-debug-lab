# ADR-0003: Static `&[&dyn Rule]` slice, not `Vec<Box<dyn Rule>>`

- **Status**: Accepted
- **Date**: 2026-05-10
- **Supersedes**: the original v0.1.0 → v0.2.0 implementation, which
  used `Vec<Box<dyn Rule>>`.

## Context

The rule registry is the answer to "what rules does the orchestrator
run?" — surfaced via `pub fn all_rules() -> ?` in `src/rules.rs`.

Two possible shapes:

1. `Vec<Box<dyn Rule>>` — heap-allocated, returns owned trait
   objects. Allows runtime extension; trivial to add closures or
   parameterised rules.
2. `&'static [&'static dyn Rule]` — pointer into a static array of
   references to zero-sized rule structs. No allocation. Compile-time
   fixed.

## Decision

Static slice. The eight rule structs (`AuthMissing`,
`BadJsonPayload`, …) are zero-sized — the rule's behaviour lives in
its `evaluate` impl, not in field state. Pointing references at
zero-sized statics is the same dispatch with no allocation.

```rust
static RULES: &[&dyn Rule] = &[
    &AuthMissing, &BadJsonPayload, &RateLimited, …
];
pub fn all_rules() -> &'static [&'static dyn Rule] { RULES }
```

## Consequences

**Positive.**

- `all_rules()` is essentially free; `diagnose` no longer pays a
  per-call heap allocation for the registry.
- The rule list is visible in source as a single static — easy to
  audit, easy to spot a missing registration.
- Compile-time fixed registry composes cleanly with `criterion`
  benches and the latency-budget test.

**Negative.**

- Cannot register a rule at runtime. A future caller who wanted to
  add a closure-based rule for testing would either need to fall
  back to a parallel registry or add a new public function.
- Adding a rule requires both a struct definition AND a
  registration line. The compiler does not flag a missing
  registration. This is the same trade-off as the previous
  implementation; clear over implicit.

**Neutral.**

- The `Rule` trait still requires `Send + Sync` so a future
  parallel orchestrator can iterate over the slice from multiple
  threads. The current sequential orchestrator runs rules at
  microsecond latency and does not need parallelism.
