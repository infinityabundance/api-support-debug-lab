# "Cannot reproduce" escalation note (template)

When the customer reports a failure but `diagnose` does not classify
the case, or the case loaded from their captured artefacts does not
reproduce the original symptom. The right framing is **what we tried,
what we observed, and what we need from the customer to make this
reproducible.**

Resist the temptation to close. Most "cannot reproduce" tickets are
real — they reveal that the captured artefact is incomplete, not that
the customer is wrong.

---

## Customer

- **Account / org**: <id>
- **Reporter**: <name, channel, originally reported at UTC>

## Original symptom (customer's words)

Paste verbatim. Do not paraphrase — the customer's exact wording often
contains the missing detail.

## What we tried

1. Loaded the case at `<fixture_dir>/case.json`.
2. Ran `api-debug-lab diagnose <case>`.
3. Result:
   - `<rule_id>` fired with confidence `<x>`, OR
   - No rule classified above the 0.60 threshold.

## What we observed

- Rule firing pattern (paste the `--explain` output):

  ```
  api-debug-lab explain <case>
  ```

- Diagnose output (paste primary + also_considered).

## Why this does not match the customer report

State the gap explicitly. Examples:

- The captured response status is 200, but the customer reports a 5xx.
  *The case captured a successful retry, not the failing request.*
- The captured body is empty, but the customer reports "validation
  failed". *The body was lost during capture.*
- The captured `now_unix` is well within tolerance, but the customer
  reports "timestamp drift" errors. *The case was captured after a
  clock-resync event.*

## Specific asks of the customer

The customer needs to capture a fresh case while the failure is live.
Walk them through it:

1. Reproduce the failure once (note the wall-clock time UTC).
2. Capture, in the same minute:
   - The full request bytes (`curl -v` or proxy log).
   - The full response bytes (status, headers, body).
   - 30 lines of server log on either side of the failure timestamp.
   - The active signing secret revision (for webhook cases).
   - The active idempotency key (for payment cases).
3. Construct a `case.json` from the capture (the schema is at
   `fixtures/cases.schema.json`; ask the customer to validate against
   it before sending).

## Holding the ticket

This ticket should remain `awaiting customer` until the fresh capture
arrives, *not* `resolved`. Set an SLA reminder:

- 24 h: nudge the customer for the capture.
- 72 h: if no response, downgrade severity but do not close.
- 7 d: close with explicit "we were unable to reproduce; please reopen
  with the requested capture" note.

## Engineering disposition

If the customer report shape is novel and the rules genuinely do not
cover it, file a follow-up to either (a) extend an existing rule or
(b) add a new rule. A "cannot reproduce" ticket is also a *coverage
gap* — fix it in the diagnostic, not just in the customer interaction.
