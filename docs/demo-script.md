# VeilPaste Demo Script

Use this script to record a 30-60 second terminal demo.

## Setup

Use a clean terminal at the repo root.

Optional:

```bash
cargo build
alias veilpaste='cargo run -q -p veilpaste-cli --bin veilpaste --'
```

If installed:

```bash
veilpaste --version
```

## Demo 1: One-Line Redaction

Narration:

```txt
I want to paste an Authorization header into AI, but not the token.
```

Command:

```bash
printf 'Authorization: Bearer sk-live-abc1234567890\n' | veilpaste
```

Expected:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

## Demo 2: Preview a curl Request

Narration:

```txt
Before I scrub a curl request, I can preview which high-confidence secrets VeilPaste will redact.
```

Command:

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

Expected:

```txt
WOULD_REDACT  High  UrlQuerySecret  line 1 col 46  -> [URL_TOKEN_1]
WOULD_REDACT  High  BearerToken     line 2 col 29  -> [BEARER_TOKEN_1]
WOULD_REDACT  High  CookieValue     line 3 col 25  -> [COOKIE_1]
```

## Demo 3: Restore After AI Edits

Narration:

```txt
VeilPaste can optionally save a local mapping, so placeholders can be restored after simple AI edits.
```

Command:

```bash
rm -rf .veilpaste
veilpaste scrub fixtures/env/openai.env --map .veilpaste/session.json > /tmp/veilpaste-redacted.env
cat /tmp/veilpaste-redacted.env
```

Expected:

```txt
OPENAI_API_KEY=[OPENAI_KEY_1]
DATABASE_PASSWORD=[ENV_SECRET_1]
```

Command:

```bash
sed 's/OPENAI_API_KEY/FIXED_OPENAI_API_KEY/' /tmp/veilpaste-redacted.env > /tmp/veilpaste-ai-output.env
veilpaste restore /tmp/veilpaste-ai-output.env --map .veilpaste/session.json
```

Expected:

```txt
FIXED_OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
DATABASE_PASSWORD=super-secret-password
```

## Closing Line

```txt
VeilPaste is a small local utility with no telemetry by default. It catches obvious secrets before AI paste to reduce security risk.
```
