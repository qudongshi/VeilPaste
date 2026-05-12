use safeprompt_core::{restore, scrub, ScrubOptions, SecretKind};
use std::fs;
use std::path::Path;

#[test]
fn scrubs_high_confidence_secrets_and_preserves_structure() {
    let input = "\
Authorization: Bearer sk-live-abc1234567890
Cookie: sessionid=prod_cookie_value; theme=dark
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
";

    let result = scrub(input, ScrubOptions::default()).expect("scrub should succeed");

    assert!(result
        .output
        .contains("Authorization: Bearer [BEARER_TOKEN_1]"));
    assert!(result.output.contains("sessionid=[COOKIE_1]"));
    assert!(result.output.contains("OPENAI_API_KEY=[OPENAI_KEY_1]"));
    assert!(!result.output.contains("sk-live-abc1234567890"));
    assert!(!result.output.contains("prod_cookie_value"));
    assert_eq!(result.mappings.len(), 3);
    assert_eq!(result.findings[0].kind, SecretKind::BearerToken);
}

#[test]
fn reuses_placeholder_for_same_secret_in_one_session() {
    let input = "\
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
backup=sk-proj-abcdefghijklmnopqrstuvwxyz
";

    let result = scrub(input, ScrubOptions::default()).expect("scrub should succeed");

    assert_eq!(result.output.matches("[OPENAI_KEY_1]").count(), 2);
    assert_eq!(result.mappings.len(), 1);
}

#[test]
fn restores_placeholders_from_mapping() {
    let input = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz";
    let scrubbed = scrub(input, ScrubOptions::default()).expect("scrub should succeed");
    let ai_output = scrubbed
        .output
        .replace("OPENAI_API_KEY", "FIXED_OPENAI_API_KEY");

    let restored = restore(&ai_output, &scrubbed.mapping_store()).expect("restore should succeed");

    assert_eq!(
        restored,
        "FIXED_OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz"
    );
}

#[test]
fn preview_reports_redactions_without_emitting_secret_values() {
    let input = "Authorization: Bearer sk-live-abc1234567890";
    let result = scrub(
        input,
        ScrubOptions {
            preview: true,
            ..ScrubOptions::default()
        },
    )
    .expect("preview should succeed");

    assert!(result.output.contains("WOULD_REDACT"));
    assert!(result.output.contains("[BEARER_TOKEN_1]"));
    assert!(!result.output.contains("sk-live-abc1234567890"));
}

#[test]
fn covers_v0_known_secret_formats() {
    let input = "\
jwt=eyJhbGciOiJIUzI1NiJ9.payload.signature
aws=AKIAABCDEFGHIJKLMNOP
github=GITHUB_TOKEN_EXAMPLE_REDACTED
stripe=STRIPE_KEY_EXAMPLE_REDACTED
url=https://example.test/path?api_key=secret_query_value
";

    let result = scrub(input, ScrubOptions::default()).expect("scrub should succeed");

    assert!(result.output.contains("[JWT_1]"));
    assert!(result.output.contains("[AWS_KEY_1]"));
    assert!(result.output.contains("[GITHUB_TOKEN_1]"));
    assert!(result.output.contains("[STRIPE_KEY_1]"));
    assert!(result.output.contains("api_key=[URL_TOKEN_1]"));
}

#[test]
fn does_not_redact_default_false_positive_types() {
    let input = "\
email=test@example.com
phone=13800138000
ip=127.0.0.1
uuid=550e8400-e29b-41d4-a716-446655440000
word=sketch
";

    let result = scrub(input, ScrubOptions::default()).expect("scrub should succeed");

    assert_eq!(result.output, input);
    assert!(result.findings.is_empty());
}

#[test]
fn strict_mode_redacts_contextual_entropy_but_default_does_not() {
    let input = "custom token: abcdefghijklmnopqrstuvwxyz1234567890";

    let default_result = scrub(input, ScrubOptions::default()).expect("scrub should succeed");
    let strict_result = scrub(
        input,
        ScrubOptions {
            strict: true,
            ..ScrubOptions::default()
        },
    )
    .expect("strict scrub should succeed");

    assert_eq!(default_result.output, input);
    assert!(strict_result.output.contains("[HIGH_ENTROPY_1]"));
}

#[test]
fn scrubs_every_positive_fixture_without_leaking_known_values() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let positive_dirs = ["env", "curl", "headers", "json", "yaml", "logs"];

    for dir in positive_dirs {
        let dir_path = fixture_root.join(dir);
        for entry in fs::read_dir(&dir_path).unwrap_or_else(|_| panic!("missing fixture dir {dir}"))
        {
            let path = entry.expect("fixture entry").path();
            if !path.is_file() {
                continue;
            }
            let input = fs::read_to_string(&path).expect("fixture should be utf-8");
            let result = scrub(&input, ScrubOptions::default()).expect("scrub should succeed");
            assert!(
                !result.findings.is_empty(),
                "expected at least one finding for {}",
                path.display()
            );
            for mapping in &result.mappings {
                assert!(
                    !result.output.contains(&mapping.original),
                    "scrubbed output leaked original value for {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn false_positive_fixtures_are_not_redacted_by_default() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/false-positives");

    for entry in fs::read_dir(&fixture_root).expect("false-positive fixture dir") {
        let path = entry.expect("fixture entry").path();
        if !path.is_file() {
            continue;
        }
        let input = fs::read_to_string(&path).expect("fixture should be utf-8");
        let result = scrub(&input, ScrubOptions::default()).expect("scrub should succeed");
        assert_eq!(
            result.output,
            input,
            "unexpected redaction in {}",
            path.display()
        );
        assert!(
            result.findings.is_empty(),
            "unexpected finding in {}",
            path.display()
        );
    }
}
