# P0 escalation note (template)

For incidents where the customer is *currently* impacted in production
and a credible "fire" is implied. Use sparingly — P0 carries a paging
cost and should not be invoked for diagnostics that can wait until
business hours.

---

## Customer

- **Account / org**: <id>
- **Plan / criticality tier**: <e.g., enterprise, regulated>
- **Reporter**: <name, channel, started at UTC>

## Symptom

One sentence stating the customer-visible failure mode and its scope.

> Example: All webhook deliveries to the customer's `/orders` endpoint
> have been returning 401 since 18:40 UTC, ~3,400 events queued.

## Reproduction

```bash
api-debug-lab replay <case>
```

…or the curl reproduction emitted by `replay`. Confirm reproduction
*before* paging — if the failure cannot be reproduced from the captured
case, treat as a "cannot reproduce" escalation (see
`escalation_template_no_repro.md`).

## Evidence (verbatim from `diagnose`)

Paste the EVIDENCE block from `diagnose <case> --format human`. Do not
summarise — the raw block is the audit trail.

## Likely cause

The rule's `likely_cause`. Add one line of customer-context translation
("their secret rotated 12 minutes before the spike began").

## Time-bounded asks

P0 escalations should request *specific* time-bounded actions, not
open-ended investigation. Example:

- Within 15 min: confirm or rule out a body-mutating proxy on the
  receiver path.
- Within 30 min: rotate the signing secret or revert the most recent
  receiver deploy.
- Within 60 min: drain the queued retry backlog after either fix.

## Hand-off artefacts

The on-call engineer cannot work without:

1. The exact bytes that arrived at the receiver (pcap or proxy access
   log).
2. The exact bytes the sender hashed.
3. Any deploy / rotation events in the last 60 minutes on either side.
4. The wall-clock skew between sender and receiver at the time of the
   first failed request.

Without these the diagnosis is bounded by what the customer reports;
with them, the receiving team can localise to one of: secret, body,
or timestamp prefix.

## Escalation chain

- Primary on-call: <rotation>
- Secondary: <rotation>
- Manager (if no acknowledgement in 10 min): <name>

## Post-incident

A P0 always produces a postmortem. Link the case file (`<fixture_dir>`)
in the post — it is the smallest reproducible artefact for the
incident timeline.
