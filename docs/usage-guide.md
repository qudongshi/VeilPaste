# VeilPaste Usage Guide

This guide shows how to install VeilPaste and use the common workflows. VeilPaste checks developer text before it reaches AI and replaces obvious secrets with readable placeholders.

## 1. Install Locally

From this checkout:

```bash
scripts/install.sh
```

Equivalent:

```bash
cargo install --path crates/veilpaste-cli
```

Verify:

```bash
veilpaste --version
```

Expected:

```txt
veilpaste 0.1.0
```

## 2. Fastest Usage

Scrub text from stdin:

```bash
printf 'Authorization: Bearer sk-live-abc1234567890\n' | veilpaste
```

Expected:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

Clipboard workflow on macOS:

```bash
pbpaste | veilpaste --quiet | pbcopy
```

Use `--quiet` when piping because stdout should contain only scrubbed content.

## 3. Preview Before Scrubbing

Use preview when you want to see what VeilPaste would redact:

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

Expected shape:

```txt
WOULD_REDACT  High  UrlQuerySecret  line 1 col 46  -> [URL_TOKEN_1]
WOULD_REDACT  High  BearerToken     line 2 col 29  -> [BEARER_TOKEN_1]
WOULD_REDACT  High  CookieValue     line 3 col 25  -> [COOKIE_1]
```

Preview never prints the original secret value.

## 4. Reversible Redaction

Scrub and save a local mapping:

```bash
rm -rf .veilpaste
veilpaste scrub fixtures/env/openai.env --map .veilpaste/session.json > /tmp/veilpaste-redacted.env
```

Inspect scrubbed output:

```bash
cat /tmp/veilpaste-redacted.env
```

Restore locally:

```bash
veilpaste restore /tmp/veilpaste-redacted.env --map .veilpaste/session.json
```

Important: `.veilpaste/session.json` contains original secrets. Do not commit it. Restore is a plain-text placeholder replacement workflow and does not guarantee that AI kept placeholders in the original semantic position.

Inspect a mapping without printing original secret values:

```bash
veilpaste map inspect --map .veilpaste/session.json
```

## 5. Check Mode

Use `check` for pre-commit hooks or CI-style local checks:

```bash
veilpaste check fixtures/headers/auth.txt
```

If secrets are found, exit code is `1` and a summary is printed.

Clean example:

```bash
veilpaste check fixtures/false-positives/common.txt
```

Expected:

```txt
No high-confidence secrets found.
```

## 6. Strict Mode

Default mode only redacts high-confidence secrets. Use `--strict` if you accept more false positives:

```bash
printf 'custom token: abcdefghijklmnopqrstuvwxyz1234567890\n' | veilpaste scrub --strict
```

Use strict mode for extra-sensitive review, not as the default daily workflow.

## 7. What To Tell Early Users

Use this 20-second explanation:

```txt
VeilPaste checks logs, curl commands, .env files, and headers before you paste them into AI. It runs locally and replaces obvious secrets with placeholders.
```

More precise version:

```txt
VeilPaste lowers the chance of leaking obvious secrets, but it does not prove a prompt is safe. Review sensitive content before sending it to AI.
```

Ask early users:

1. Did you paste logs, curl, `.env`, headers, or stack traces into AI in the last 30 days?
2. Would you install this as a CLI?
3. Which workflow matters most next: Chrome, DevTools, Postman, Cursor, or Claude Code?
