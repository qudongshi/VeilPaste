# Changelog

All notable changes to VeilPaste will be documented in this file.

## 0.1.0 - Unreleased

### Added

- Rust workspace with `veilpaste-core`, `veilpaste-rules`, and `veilpaste-cli`.
- CLI scrub, preview, strict, restore, check, and explain flows.
- High-confidence secret redaction for Bearer tokens, JWTs, cookies, OpenAI keys, AWS keys, GitHub tokens, Stripe keys, `.env` secrets, and URL query secrets.
- Reversible local mapping store and restore flow.
- Fixture-backed tests for positive and false-positive cases.
- Threat model, README, install script, and CI workflow.

