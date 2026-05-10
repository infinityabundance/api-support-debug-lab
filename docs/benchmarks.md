# Benchmarks

Baseline numbers for `diagnose` over the bundled fixtures. Reproduce with:

```bash
cargo bench --bench diagnose
```

Numbers below are **median wall-clock** time per `diagnose(case)` call,
measured by `criterion 0.5` in `--quick` mode on a Linux laptop. The
quick mode runs ~10 iterations per benchmark; the headline `cargo bench`
without `--quick` runs ~100 iterations and reports tighter confidence
intervals but the same medians within ~5%.

## Baseline (v0.2.0)

| Fixture                              | Median time | Notes                                     |
| ------------------------------------ | ----------- | ----------------------------------------- |
| `auth_missing`                       | ~2.0 µs     | header presence + 401 status check         |
| `bad_json_payload`                   | ~2.1 µs     | serde_json parse over a small body         |
| `rate_limited`                       | ~2.1 µs     | header math, no body parse                 |
| `webhook_signature_invalid`          | ~3.9 µs     | full HMAC-SHA256 recompute                 |
| `webhook_signature_invalid_stale`    | ~3.9 µs     | HMAC + timestamp drift                     |
| `timeout_retry`                      | ~4.3 µs     | full log scan; per-line JSON-or-text autodetect |
| `config_dns_error`                   | ~2.2 µs     | URL parse + Hamming distance               |

End-to-end `diagnose` is **single-digit microseconds** for every bundled
case. The cost is dominated by HMAC for webhook cases and by the log
scan for `timeout_retry`. There is no allocation hotspot to optimise
without sacrificing readability.

## What this is *not*

These numbers are not a load benchmark. They are a sanity check that:

- the rule layer does not accidentally allocate or block on I/O,
- the per-line JSON autodetect on the log scan does not regress order
  of magnitude versus pure text parsing,
- a future change that adds a heavy dependency (regex, chrono) will be
  visible in the diff.

If a rule's median moves by more than ~30% on a re-bench, treat it as
a regression worth investigating.
