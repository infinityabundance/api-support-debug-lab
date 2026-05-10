// SPDX-License-Identifier: Apache-2.0

//! Property-based tests via `proptest`.
//!
//! Each property generates random `Case` values within the documented
//! schema and checks an invariant the rule layer must preserve. These
//! catch panics, non-determinism, and silent over-classification on
//! shapes the bundled fixtures do not cover.

use std::collections::BTreeMap;
use std::path::PathBuf;

use api_debug_lab::cases::{
    Case, Context, EnvelopeFormat, IdempotencyCtx, Request, Response, Severity, WebhookCtx,
};
use api_debug_lab::rules::diagnose;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn severity_strategy() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
    ]
}

fn lower_ascii_token() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z][a-z0-9_-]{0,31}").unwrap()
}

fn header_value() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[ -~]{0,127}").unwrap()
}

fn headers_strategy() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::btree_map(lower_ascii_token(), header_value(), 0..6)
}

fn body_strategy() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(proptest::string::string_regex(r#"[ -~]{0,256}"#).unwrap())
}

fn url_strategy() -> impl Strategy<Value = String> {
    // Generate a small set of plausible URLs covering match / mismatch
    // against the documented base.
    prop_oneof![
        Just("https://api.acme-co.example/v1/events".to_string()),
        Just("https://api.acme-co.example/v1/health".to_string()),
        Just("https://api.acme-co.exemple/v1/health".to_string()),
        Just("https://api.acme.example/v1/events".to_string()),
        Just("http://api.acme-co.example/v1/events".to_string()),
        Just("https://customer.acme-co.example/hooks/orders".to_string()),
    ]
}

fn request_strategy() -> impl Strategy<Value = Request> {
    (
        prop_oneof![Just("GET"), Just("POST"), Just("PUT"), Just("DELETE")],
        url_strategy(),
        headers_strategy(),
        body_strategy(),
    )
        .prop_map(|(method, url, headers, body)| Request {
            method: method.to_string(),
            url,
            headers,
            body,
        })
}

fn response_strategy() -> impl Strategy<Value = Option<Response>> {
    proptest::option::of(
        (100u16..=599u16, headers_strategy(), body_strategy()).prop_map(
            |(status, headers, body)| Response {
                status,
                headers,
                body,
            },
        ),
    )
}

fn context_strategy() -> impl Strategy<Value = Context> {
    (
        any::<bool>(),
        proptest::option::of(Just("https://api.acme-co.example/v1".to_string())),
        proptest::option::of(0u64..=60_000),
        proptest::option::of(1_000_000_000i64..=2_000_000_000),
    )
        .prop_map(
            |(auth_required, expected_base_url, client_deadline_ms, now_unix)| Context {
                auth_required,
                expected_base_url,
                webhook: None,
                idempotency: None,
                client_deadline_ms,
                now_unix,
            },
        )
}

fn case_strategy() -> impl Strategy<Value = Case> {
    (
        lower_ascii_token(),
        proptest::string::string_regex(r#"[ -~]{10,128}"#).unwrap(),
        severity_strategy(),
        request_strategy(),
        response_strategy(),
        context_strategy(),
    )
        .prop_map(
            |(name, description, severity, request, response, context)| Case {
                name,
                description,
                severity,
                request,
                response,
                context,
                expected_rule_id: None,
                log_path: None,
                fixture_dir: PathBuf::from("/tmp/proptest-not-used"),
            },
        )
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// No rule may panic on any case that the type system accepts. Schema
    /// validation enforces a stricter shape than this strategy generates,
    /// so passing here is a stronger guarantee.
    #[test]
    fn diagnose_never_panics(case in case_strategy()) {
        let _ = diagnose(&case);
    }

    /// Diagnosing the same case twice must produce equal reports.
    #[test]
    fn diagnose_is_idempotent(case in case_strategy()) {
        let a = diagnose(&case);
        let b = diagnose(&case);
        prop_assert_eq!(a, b);
    }

    /// Confidence must always be a finite number in [0, 1].
    #[test]
    fn confidence_is_well_formed(case in case_strategy()) {
        let report = diagnose(&case);
        if let Some(d) = report.primary {
            prop_assert!(d.confidence.is_finite(), "non-finite confidence");
            prop_assert!((0.0..=1.0).contains(&d.confidence), "out-of-range: {}", d.confidence);
        }
        for d in report.also_considered {
            prop_assert!(d.confidence.is_finite());
            prop_assert!((0.0..=1.0).contains(&d.confidence));
        }
    }

    /// `also_considered` is sorted by descending confidence and never
    /// exceeds the primary's confidence.
    #[test]
    fn arbitration_ordering_is_monotone(case in case_strategy()) {
        let report = diagnose(&case);
        if let Some(primary) = &report.primary {
            for d in &report.also_considered {
                prop_assert!(
                    d.confidence <= primary.confidence,
                    "primary {} < also-considered {}", primary.confidence, d.confidence
                );
            }
        }
        let confidences: Vec<f32> =
            report.also_considered.iter().map(|d| d.confidence).collect();
        for pair in confidences.windows(2) {
            prop_assert!(pair[0] >= pair[1], "also_considered not sorted desc");
        }
    }
}

// ---------------------------------------------------------------------------
// Adversarial inputs (hand-written, not generated)
// ---------------------------------------------------------------------------

fn pathological_base() -> Case {
    Case {
        name: "adversarial".to_string(),
        description: "x".repeat(64),
        severity: Severity::Low,
        request: Request {
            method: "POST".to_string(),
            url: "https://api.acme-co.example/v1/events".to_string(),
            headers: BTreeMap::new(),
            body: None,
        },
        response: None,
        context: Context::default(),
        expected_rule_id: None,
        log_path: None,
        fixture_dir: PathBuf::from("/tmp/adversarial"),
    }
}

#[test]
fn one_mib_body_does_not_panic() {
    let mut c = pathological_base();
    c.request.body = Some("a".repeat(1024 * 1024));
    c.request
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    let _ = diagnose(&c);
}

#[test]
fn nul_byte_body_does_not_panic() {
    let mut c = pathological_base();
    c.request.body = Some("\u{0000}".to_string());
    c.request
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    let _ = diagnose(&c);
}

#[test]
fn far_future_timestamp_drift_is_handled() {
    let mut c = pathological_base();
    c.context.now_unix = Some(1_700_000_000);
    c.context.webhook = Some(WebhookCtx {
        secret_path: "secret.txt".to_string(),
        signature_header: "x-signature".to_string(),
        timestamp_header: "x-webhook-timestamp".to_string(),
        tolerance_seconds: 300,
        envelope_format: EnvelopeFormat::default(),
    });
    c.request
        .headers
        .insert("x-webhook-timestamp".to_string(), "9999999999".to_string());
    let report = diagnose(&c);
    // No secret available at /tmp/adversarial/secret.txt, so the signature
    // rule cannot fire; only the timestamp rule may. It should still report
    // *some* drift without panicking.
    if let Some(d) = report.primary {
        assert!(d.confidence.is_finite());
    }
}

#[test]
fn empty_idempotency_does_not_panic() {
    let mut c = pathological_base();
    c.context.idempotency = Some(IdempotencyCtx {
        header: "idempotency-key".to_string(),
        stored_body_sha256: "0".repeat(64),
    });
    let _ = diagnose(&c);
}

#[test]
fn extremely_long_url_does_not_panic() {
    let mut c = pathological_base();
    c.request.url = format!("https://example.com/{}", "a".repeat(8192));
    c.context.expected_base_url = Some("https://api.acme-co.example/v1".to_string());
    let _ = diagnose(&c);
}
