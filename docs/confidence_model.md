# Confidence model

This document explains the per-rule confidence values emitted by `diagnose`
and how they are held accountable. The numbers in `src/rules.rs` are not
arbitrary; they follow the rubric below and are validated against the
labelled corpus by `tests/calibration.rs`.

## Rubric

Confidence is a value in `[0.0, 1.0]` interpreted as the rule's posterior
belief that it is the right diagnosis for this case. The bands:

| Band         | Range        | Meaning                                                             |
| ------------ | ------------ | ------------------------------------------------------------------- |
| Dispositive  | 0.90 – 0.95  | Direct mathematical or structural proof; not just correlated.        |
| Strong       | 0.85 – 0.89  | Two or more independent signals point at the same rule.              |
| Moderate     | 0.65 – 0.84  | One robust signal; arbitration may still flip if a stronger rule fires. |
| Inadmissible | < 0.60       | Below the classification threshold; reported as "unclassified."     |

A rule emits a value at the top of its band only when *every* documented
signal is present. Each missing signal moves the value down within the band;
falling below the band's floor means the rule does not fire.

## Per-rule rationale

### `auth_missing`

- 0.95 (top of dispositive): `Authorization` header literally absent on a
  documented `auth_required` route **and** response status `401`.
- 0.60 (top of moderate): header absent, route is auth-required, but no
  401 response observed (rare; usually means the case is mid-flight).
- Below 0.60: any of the three signals missing → rule does not fire.

### `bad_json_payload`

- 0.95: `Content-Type: application/json` and `serde_json` reports a parse
  error and response status is `400` or `422`.
- 0.70: same, but no 4xx response status (server may have accepted bad
  bytes silently — rare).

### `rate_limited`

- 0.95: response status is `429` **and** at least one of `Retry-After`,
  `X-RateLimit-Remaining: 0`, or `X-RateLimit-Reset` is present.
- 0.85: 429 with rate-limit headers but `X-RateLimit-Remaining` is
  non-zero (transient burst, not sustained).
- 0.70: 429 with no rate-limit headers (the rule is still right, but
  has no math to back it up).

### `webhook_signature_mismatch`

- 0.92 (always, when fires): HMAC mismatch is dispositive — either the
  secret, the body, or the timestamp prefix differs. The confidence is
  flat because there is no weaker form of "the digests don't match."

### `webhook_timestamp_stale`

- 0.90: drift exceeds `tolerance_seconds × 10` — almost certainly a
  systemic clock or queue issue, not transient skew.
- 0.85: drift exceeds `tolerance_seconds` but is within 10× tolerance —
  could be benign clock skew on a single host.

### `timeout_retry`

- 0.90: at least one stream's derived elapsed exceeds the documented
  client deadline.
- 0.85: max attempt observed ≥ 3 (retry exhaustion) without deadline
  evidence.
- 0.85: client deadline is documented even if not exceeded — the
  infrastructure intent matches retry behaviour.
- 0.65: only 2 timeouts observed and no deadline / no retry exhaustion
  evidence.

### `config_dns_error`

- 0.90: hostname differs by ≤ 2 characters from the documented host
  (typo / TLD near-miss detected by Hamming distance on the rightmost
  differing label).
- 0.80: scheme differs (e.g., `http` vs `https`).
- 0.75: hostname differs but not in a near-miss pattern (configuration
  drift rather than typo).

### `idempotency_collision`

- 0.93: response status is exactly `422` and the recomputed body SHA-256
  differs from the stored hash. Stripe / many real APIs return 422 for
  this exact case.
- 0.80: response status is some other 4xx; same hash mismatch.
- 0.70: hash mismatch with non-error response (the server accepted but
  this is the customer's first send under this key — rare).

## Calibration

`tests/calibration.rs` runs every case with an embedded
`expected_rule_id` label (currently 36 cases: 14 bundled positives,
11 bundled negatives, and 11 hand-written `_calibration/` edge cases)
through `diagnose`, then enforces five separate properties:

### 1. Aggregate Brier score

> Brier = mean over (case, rule) pairs of (predicted_probability − ground_truth)²

where `predicted_probability` is the rule's emitted confidence (0.0
if the rule does not fire) and `ground_truth` is `1.0` if this rule
should fire on this case according to the label, else `0.0`.

The test asserts `aggregate Brier ≤ 0.05` over **36 cases × 8 rules
= 288 (case, rule) pairs**. The average per-pair error stays below
`√0.05 ≈ 0.22`.

### 2. Per-rule Brier score

The aggregate metric hides the failure mode "average is fine, rule X
is miscalibrated." A per-rule breakdown asserts each rule's Brier ≤
**0.08** independently. The threshold is looser because each rule
sees only ~36 (case, rule) pairs rather than 288.

### 3. Expected Calibration Error (ECE)

The standard reliability metric alongside Brier. Predictions are
binned into deciles; per bin we compute the absolute deviation
between mean predicted probability and empirical accuracy; the
result is weighted by bin occupancy and summed:

> ECE = Σ (n_bin / n_total) × |mean_predicted − empirical_accuracy|

The test asserts `ECE ≤ 0.05`. Lower means the rule's stated
confidence tracks its real accuracy across the confidence range.

### 4. Primary-classification accuracy is 100%

Every labelled case must classify to exactly the labelled
`expected_rule_id`, or remain unclassified when the label is `null`.
Any drift breaks the test loudly with the offending case named.

### 5. Calibration regression canary

`tests/calibration_regression.rs` (gated behind the
`calibration_canary` feature) simulates a deliberately
miscalibrated rule and asserts the production Brier check **would
have failed** under that miscalibration. CI runs this in a separate
job. A green canary test is what proves the calibration framework
above is load-bearing rather than ceremonial.

### Maintenance

If you tighten the rubric or add a rule, update this document, the
rule code, and the enrolled `expected_rule_id` labels. The plan, the
rubric, the labels, and the rule code must all agree. The calibration
test is your alarm if any of them drift.
