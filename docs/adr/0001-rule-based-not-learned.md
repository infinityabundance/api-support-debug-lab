# ADR-0001: Rule-based classification, not machine-learned

- **Status**: Accepted
- **Date**: 2026-05-10

## Context

The lab classifies API failures into one of eight known modes
(missing auth, bad JSON, rate limit, webhook signature, webhook
timestamp, timeout retry, DNS, idempotency collision). The natural
question is whether the classifier should be hand-written rules or
a learned model (logistic regression, gradient-boosted trees, a
small transformer).

Real production support runbooks at companies the lab is modelled
on (Stripe, Twilio, Cloudflare) are predominantly rule-based. The
question is whether the *demo* should follow them or use ML for
recruiter-visible novelty.

## Decision

Rule-based, with a documented confidence rubric and Brier-score
calibration test. The classifier is eight `Rule` impls with
hand-tuned confidence values held accountable by aggregate Brier ≤
0.05, per-rule Brier ≤ 0.08, and ECE ≤ 0.05 over a 36-case labelled
corpus.

## Consequences

**Positive.**

- The "evidence" surface is intelligible: each rule lists exactly
  which case fields it consulted and why. A learned model would
  produce a feature-importance vector, which is less useful in a
  customer-facing escalation note.
- Confidence is calibrated, not predicted. Brier and ECE stay
  meaningful with 36 cases; an ML model would need 10–100× more
  data to be competitive.
- The escalation note is the artefact a real support engineer
  would write. Rule-based output maps onto it cleanly.

**Negative.**

- Adding a new failure mode means writing a new rule, not
  retraining. This is by design but limits scaling to many modes.
- Confidence values are hand-tuned. The calibration test catches
  drift; the regression canary
  (`tests/calibration_regression.rs`) proves the test is
  load-bearing rather than ceremonial.

**Neutral.**

- A future revision could add a learned re-ranker on top of the
  rule outputs without changing the rule layer. Out of scope for
  v0.x.
