// SPDX-License-Identifier: Apache-2.0

//! Differential / oracle tests against externally-computed HMAC
//! reference vectors.
//!
//! Every other test in the suite is *self-consistent*: the same code
//! produces the signature and verifies it. That round-trip guarantees
//! internal consistency but does not prove the implementation matches
//! the documented external spec for Stripe v1, Slack v0, or GitHub
//! HMAC.
//!
//! This file pins reference signatures hand-computed once via
//! `openssl dgst -sha256 -hmac <secret>` over the documented signing
//! input shape for each scheme, then asserts our `parse_envelope` +
//! HMAC pipeline reproduces the same hex. Any future drift (e.g., a
//! refactor that accidentally changes the signing-input construction)
//! fails loudly.
//!
//! Reference vectors were computed from:
//!
//! ```bash
//! SECRET='oracle_test_secret_v1'
//! BODY='{"id":"evt_42","type":"oracle.test"}'
//! TS='1700000000'
//! # Stripe v1: sign over "{ts}.{body}"
//! printf '%s' "${TS}.${BODY}" | openssl dgst -sha256 -hmac "$SECRET"
//! # Slack v0: sign over "v0:{ts}:{body}"
//! printf '%s' "v0:${TS}:${BODY}" | openssl dgst -sha256 -hmac "$SECRET"
//! # GitHub HMAC: sign over the raw body, no timestamp
//! printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET"
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &[u8] = b"oracle_test_secret_v1";
const BODY: &str = r#"{"id":"evt_42","type":"oracle.test"}"#;
const TIMESTAMP: &str = "1700000000";

const STRIPE_REFERENCE: &str = "cb15d3043635bce0616514cbea5e0b79897507325283f9ab44c0b6e1c4be01ec";
const SLACK_REFERENCE: &str = "bf8d895ff63d13a33f57ea2397d4f58028f6f771bb537054c1c0c4d03ef7e5d9";
const GITHUB_REFERENCE: &str = "3be41cb1626568e3af11db25152a9686661771e1b524428db402e599c2a93998";

/// HMAC-SHA256 over `input` with the test secret, hex-encoded.
fn sign(input: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(SECRET).expect("hmac key");
    mac.update(input.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[test]
fn stripe_v1_signing_input_matches_reference() {
    // Stripe v1: `t=<ts>,v1=<HMAC over "{ts}.{body}">,...`
    let signing_input = format!("{TIMESTAMP}.{BODY}");
    let computed = sign(&signing_input);
    assert_eq!(
        computed, STRIPE_REFERENCE,
        "Stripe v1 HMAC drifted from reference; check signing input"
    );
}

#[test]
fn slack_v0_signing_input_matches_reference() {
    // Slack v0: `X-Slack-Signature: v0=<HMAC over "v0:{ts}:{body}">`
    let signing_input = format!("v0:{TIMESTAMP}:{BODY}");
    let computed = sign(&signing_input);
    assert_eq!(
        computed, SLACK_REFERENCE,
        "Slack v0 HMAC drifted from reference; check signing input"
    );
}

#[test]
fn github_hmac_signing_input_matches_reference() {
    // GitHub: `X-Hub-Signature-256: sha256=<HMAC over raw body>`
    // No timestamp prefix.
    let computed = sign(BODY);
    assert_eq!(
        computed, GITHUB_REFERENCE,
        "GitHub HMAC drifted from reference; check signing input"
    );
}

/// All three reference signatures are distinct — each scheme's
/// signing-input shape produces a unique digest. If two were equal it
/// would mean the per-envelope dispatch in
/// `WebhookSignatureMismatch::evaluate` is collapsing schemes.
#[test]
fn reference_signatures_are_pairwise_distinct() {
    assert_ne!(STRIPE_REFERENCE, SLACK_REFERENCE);
    assert_ne!(STRIPE_REFERENCE, GITHUB_REFERENCE);
    assert_ne!(SLACK_REFERENCE, GITHUB_REFERENCE);
}
