// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::cases::Case;

const EMBEDDED_FIXTURE_DIR: &str = "<api-debug-lab:embedded-fixtures>";

struct EmbeddedCase {
    name: &'static str,
    case_json: &'static str,
    server_log: Option<&'static str>,
    secret: Option<&'static str>,
    positive: bool,
}

static CASES: &[EmbeddedCase] = &[
    EmbeddedCase {
        name: "auth_missing",
        case_json: include_str!("../fixtures/cases/auth_missing/case.json"),
        server_log: Some(include_str!("../fixtures/cases/auth_missing/server.log")),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "bad_json_payload",
        case_json: include_str!("../fixtures/cases/bad_json_payload/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/bad_json_payload/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "config_dns_error",
        case_json: include_str!("../fixtures/cases/config_dns_error/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/config_dns_error/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "idempotency_collision",
        case_json: include_str!("../fixtures/cases/idempotency_collision/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/idempotency_collision/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "rate_limited",
        case_json: include_str!("../fixtures/cases/rate_limited/case.json"),
        server_log: Some(include_str!("../fixtures/cases/rate_limited/server.log")),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "timeout_retry",
        case_json: include_str!("../fixtures/cases/timeout_retry/case.json"),
        server_log: Some(include_str!("../fixtures/cases/timeout_retry/server.log")),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "timeout_retry_jsonl",
        case_json: include_str!("../fixtures/cases/timeout_retry_jsonl/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/timeout_retry_jsonl/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "timeout_retry_midnight_rollover",
        case_json: include_str!("../fixtures/cases/timeout_retry_midnight_rollover/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/timeout_retry_midnight_rollover/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "timeout_retry_partial_outage",
        case_json: include_str!("../fixtures/cases/timeout_retry_partial_outage/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/timeout_retry_partial_outage/server.log"
        )),
        secret: None,
        positive: true,
    },
    EmbeddedCase {
        name: "webhook_github_hmac",
        case_json: include_str!("../fixtures/cases/webhook_github_hmac/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/webhook_github_hmac/server.log"
        )),
        secret: Some(include_str!(
            "../fixtures/cases/webhook_github_hmac/secret.txt"
        )),
        positive: true,
    },
    EmbeddedCase {
        name: "webhook_signature_invalid",
        case_json: include_str!("../fixtures/cases/webhook_signature_invalid/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/webhook_signature_invalid/server.log"
        )),
        secret: Some(include_str!(
            "../fixtures/cases/webhook_signature_invalid/secret.txt"
        )),
        positive: true,
    },
    EmbeddedCase {
        name: "webhook_signature_invalid_stale",
        case_json: include_str!("../fixtures/cases/webhook_signature_invalid_stale/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/webhook_signature_invalid_stale/server.log"
        )),
        secret: Some(include_str!(
            "../fixtures/cases/webhook_signature_invalid_stale/secret.txt"
        )),
        positive: true,
    },
    EmbeddedCase {
        name: "webhook_slack_v0",
        case_json: include_str!("../fixtures/cases/webhook_slack_v0/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/webhook_slack_v0/server.log"
        )),
        secret: Some(include_str!(
            "../fixtures/cases/webhook_slack_v0/secret.txt"
        )),
        positive: true,
    },
    EmbeddedCase {
        name: "webhook_stripe_v1",
        case_json: include_str!("../fixtures/cases/webhook_stripe_v1/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/webhook_stripe_v1/server.log"
        )),
        secret: Some(include_str!(
            "../fixtures/cases/webhook_stripe_v1/secret.txt"
        )),
        positive: true,
    },
    EmbeddedCase {
        name: "host_match",
        case_json: include_str!("../fixtures/cases/_negatives/host_match/case.json"),
        server_log: None,
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "idempotency_clean",
        case_json: include_str!("../fixtures/cases/_negatives/idempotency_clean/case.json"),
        server_log: None,
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "log_injection_in_body",
        case_json: include_str!("../fixtures/cases/_negatives/log_injection_in_body/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/_negatives/log_injection_in_body/server.log"
        )),
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "non_429_high_traffic",
        case_json: include_str!("../fixtures/cases/_negatives/non_429_high_traffic/case.json"),
        server_log: None,
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "single_timeout_no_retry",
        case_json: include_str!("../fixtures/cases/_negatives/single_timeout_no_retry/case.json"),
        server_log: Some(include_str!(
            "../fixtures/cases/_negatives/single_timeout_no_retry/server.log"
        )),
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "upstream_401",
        case_json: include_str!("../fixtures/cases/_negatives/upstream_401/case.json"),
        server_log: None,
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "valid_json_schema_fail",
        case_json: include_str!("../fixtures/cases/_negatives/valid_json_schema_fail/case.json"),
        server_log: None,
        secret: None,
        positive: false,
    },
    EmbeddedCase {
        name: "webhook_clean",
        case_json: include_str!("../fixtures/cases/_negatives/webhook_clean/case.json"),
        server_log: None,
        secret: Some(include_str!(
            "../fixtures/cases/_negatives/webhook_clean/secret.txt"
        )),
        positive: false,
    },
    EmbeddedCase {
        name: "webhook_github_hmac_clean",
        case_json: include_str!("../fixtures/cases/_negatives/webhook_github_hmac_clean/case.json"),
        server_log: None,
        secret: Some(include_str!(
            "../fixtures/cases/_negatives/webhook_github_hmac_clean/secret.txt"
        )),
        positive: false,
    },
    EmbeddedCase {
        name: "webhook_slack_v0_clean",
        case_json: include_str!("../fixtures/cases/_negatives/webhook_slack_v0_clean/case.json"),
        server_log: None,
        secret: Some(include_str!(
            "../fixtures/cases/_negatives/webhook_slack_v0_clean/secret.txt"
        )),
        positive: false,
    },
    EmbeddedCase {
        name: "webhook_stripe_v1_clean",
        case_json: include_str!("../fixtures/cases/_negatives/webhook_stripe_v1_clean/case.json"),
        server_log: None,
        secret: Some(include_str!(
            "../fixtures/cases/_negatives/webhook_stripe_v1_clean/secret.txt"
        )),
        positive: false,
    },
];

pub(crate) fn positive_names() -> Vec<String> {
    let mut names: Vec<String> = CASES
        .iter()
        .filter(|case| case.positive)
        .map(|case| case.name.to_string())
        .collect();
    names.sort();
    names
}

pub(crate) fn load(name: &str) -> Option<Case> {
    let fixture = CASES.iter().find(|case| case.name == name)?;
    let mut case: Case = serde_json::from_str(fixture.case_json)
        .unwrap_or_else(|err| panic!("embedded fixture {name} is invalid JSON: {err}"));
    case.fixture_dir = PathBuf::from(EMBEDDED_FIXTURE_DIR);
    case.log_path = None;
    Some(case)
}

pub(crate) fn log_for(name: &str, fixture_dir: &Path) -> Option<String> {
    if !is_embedded_fixture_dir(fixture_dir) {
        return None;
    }
    CASES
        .iter()
        .find(|case| case.name == name)
        .and_then(|case| case.server_log)
        .map(str::to_string)
}

pub(crate) fn secret_for(name: &str, fixture_dir: &Path) -> Option<Vec<u8>> {
    if !is_embedded_fixture_dir(fixture_dir) {
        return None;
    }
    CASES
        .iter()
        .find(|case| case.name == name)
        .and_then(|case| case.secret)
        .map(|secret| secret.trim_end_matches('\n').as_bytes().to_vec())
}

fn is_embedded_fixture_dir(path: &Path) -> bool {
    path == Path::new(EMBEDDED_FIXTURE_DIR)
}
