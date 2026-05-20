# VeilPaste

Paste into AI without leaking obvious secrets.

VeilPaste checks text before it reaches AI tools. It looks for common developer secrets such as API keys, Bearer tokens, cookies, private keys, and database URLs, then replaces them with readable placeholders.

It runs locally by default. It does not upload your prompt, store secret values, or require an account.

## Quick Demo

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste
```

Output:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

Clipboard workflow:

```bash
pbpaste | veilpaste --quiet | pbcopy
```

Preview workflow:

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

Full walkthrough: [docs/usage-guide.md](docs/usage-guide.md).

## Chrome Extension

The Chrome extension pauses risky paste operations on ChatGPT, Claude, Perplexity, Doubao, and Qwen.

When VeilPaste finds a possible leak, you can choose:

- paste without redaction
- redact this paste
- always redact this kind of paste on the current site

Load it from `chrome-extension/` while testing locally.

## Reversible Redaction

For local file-editing workflows, VeilPaste can keep a local restore map:

```bash
veilpaste scrub .env --map .veilpaste/session.json > redacted.env
```

Example:

```txt
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
```

becomes:

```txt
OPENAI_API_KEY=[OPENAI_KEY_1]
```

If AI returns an edited file containing `[OPENAI_KEY_1]`, restore it locally:

```bash
veilpaste restore ai-output.env --map .veilpaste/session.json
```

The map contains original secrets. Keep it local and do not commit it.

## Commands

```bash
veilpaste < input.txt
veilpaste scrub input.txt
veilpaste scrub input.txt --map .veilpaste/session.json
veilpaste scrub input.txt --preview
veilpaste scrub input.txt --strict
veilpaste --quiet < input.txt
veilpaste restore output.txt --map .veilpaste/session.json
veilpaste check input.txt
veilpaste explain input.txt
```

Use `--quiet` when stdout should contain only redacted text.

## Install From This Checkout

```bash
scripts/install.sh
```

Equivalent command:

```bash
cargo install --path crates/veilpaste-cli
```

## What It Catches

VeilPaste focuses on high-confidence developer secrets:

- Bearer tokens and basic auth credentials
- API key headers
- JWTs and cookie values
- OpenAI, AWS, GitHub, and Stripe keys
- `.env` secret values
- database and service URLs
- Slack and Discord webhook URLs
- URL username/password values
- PEM private keys
- npm, pypirc, and Docker registry credentials
- URL query secrets such as `token`, `api_key`, `secret`, and `password`

It does not redact ordinary email addresses, phone numbers, IP addresses, names, project names, or UUIDs by default.

See [Known Misses](docs/known-misses.md) for unsupported cases.

## Trust Boundaries

- Local processing by default.
- No telemetry by default.
- No account required.
- Mapping files stay on your machine.
- Redaction lowers risk, but it does not prove a prompt is safe to send.

Read [docs/threat-model.md](docs/threat-model.md) before using VeilPaste with highly sensitive data.
