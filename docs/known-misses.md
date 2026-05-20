# Known Misses

VeilPaste is a small developer utility that reduces AI-paste security risk by catching known high-confidence developer secrets before paste.

This page is intentionally explicit about current gaps. The goal is to make unsupported formats visible instead of implying complete protection.

## Currently Not Guaranteed

VeilPaste V0 does not guarantee detection for:

- Every `DATABASE_URL`, `REDIS_URL`, `MONGO_URI`, DSN, or webhook variant.
- Kubernetes Secret YAML values.
- GitHub Actions logs with masked or multiline secret fragments.
- Terraform variable files.
- Google service account JSON private keys.
- Anthropic, Gemini, Azure OpenAI, Slack, Discord, or Telegram tokens beyond currently implemented known patterns.
- PII such as names, addresses, phone numbers, ordinary email addresses, or normal IP addresses.
- Internal project names, customer names, private hostnames, or business-sensitive prose.
- Secrets hidden inside binary, compressed, encrypted, or non-UTF-8 files.

## Restore Boundary

`veilpaste restore` is a plain-text placeholder replacement workflow. It can restore placeholders that are present in the AI-edited output, but it does not prove that those placeholders are still in the correct semantic position.

Use restore for simple config-editing workflows, not as a security guarantee.

Mapping files include `session_id` and `created_at` metadata and are written with restrictive file permissions on Unix-like systems. They still contain live original secrets.

## Realistic Coverage

The repository includes an internal realistic fixture report under `crates/veilpaste-core/tests/realistic_report.rs`. It checks `fixtures/realistic/manifest.json` for expected redactions, protected spans, known misses, and false positives.

This report is intentionally test-only for now. There is no stable public `veilpaste fixture-report` command yet.

## Reporting Misses

When reporting a miss, include:

- Input type, such as `.env`, curl, Docker config, npmrc, or log file.
- A minimal redacted example with fake secret values.
- Which substring should be redacted.
- Which nearby substrings must not be redacted.

Do not send real secrets in reports.
