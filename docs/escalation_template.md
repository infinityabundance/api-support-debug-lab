# Support escalation note: webhook_signature_invalid

A worked example of the kind of note this lab is designed to produce. The
`api-debug-lab report webhook_signature_invalid` command emits the same
shape automatically; this document shows the human-readable result a
support engineer would paste into a ticket.

## Customer symptom

> "Our webhook deliveries to `https://customer.acme-co.example/hooks/orders`
> started returning 401 around 18:40 UTC after we rotated our signing
> secrets. We've double-checked the new secret on our side."

## Reproduction

```bash
api-debug-lab replay webhook_signature_invalid
```

Reproduces the same signature mismatch deterministically. The bundled
fixture includes the request, response, server log, and the secret used
to recompute the expected HMAC.

## Evidence

- `X-Signature` provided by the sender:
  `sha256=00000000000000000000000000000000000000000000000000000000deadbeef`
- HMAC-SHA256 recomputed over `"{x-webhook-timestamp}.{raw_body}"` using the
  bundled secret:
  `f700578c0b5bfcb596260bf652581eabb9c4bc2332d584b99ec8cdaea0be906f`
- Signing input length: 57 bytes.
- Timestamp drift: 60 seconds (within the 300 second tolerance — *not* a
  staleness issue).
- Server log: status 401, reason `signature_invalid`, latency 4 ms.

## Likely cause

The signature on the wire was not generated from the active signing secret
*and* the exact body bytes the receiver hashed. The most common shapes:

1. The secret rotated on one side but the redeploy lagged on the other.
2. A proxy or middleware re-serialised the body (whitespace or key order
   changes) between signing and delivery.
3. The signer is hashing a parsed-and-re-serialised JSON object rather than
   the raw bytes.

## Customer-facing next steps

1. Confirm the secret revision currently active on the **sending** side
   (not the dashboard).
2. Verify the receiver hashes the **raw** request body, not a parsed copy.
3. Check for a proxy / WAF / rewrite rule that may modify the body before
   the receiver validates the signature.
4. Re-test with a freshly generated webhook from the dashboard and capture
   the wire bytes (`tcpdump` or proxy access log).

## Engineering escalation

If steps 1–3 are clean and the customer can reproduce with a fresh send,
hand off with:

- The exact bytes that arrived at the receiver (hex-dump or pcap).
- The exact bytes the sender hashed (what their HMAC implementation saw).
- The wall-clock timestamp delta between sender and receiver at the time
  of signing.
- The signing-secret rotation history on the sender's side for the last
  24 hours.

The combination of recomputed HMAC, signing-input length, and observed
drift is enough for the receiving team to localise the divergence to one
of: secret, body, or timestamp prefix.
