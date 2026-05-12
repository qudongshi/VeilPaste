# SafePrompt Demo Script

Use this script to record a 30-60 second terminal demo.

## Setup

Use a clean terminal at the repo root.

Optional:

```bash
cargo build
alias safeprompt='cargo run -q -p safeprompt-cli --bin safeprompt --'
```

If installed:

```bash
safeprompt --version
```

## Demo 1: One-Line Redaction

Narration:

```txt
I want to paste an Authorization header into AI, but not the token.
```

Command:

```bash
printf 'Authorization: Bearer sk-live-abc1234567890\n' | safeprompt
```

Expected:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

## Demo 2: Preview a curl Request

Narration:

```txt
Before I scrub a curl request, I can preview exactly what SafePrompt will redact.
```

Command:

```bash
safeprompt scrub fixtures/curl/request.curl --preview
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
SafePrompt can save a local mapping, so placeholders can be restored after AI edits.
```

Command:

```bash
rm -rf .safeprompt
safeprompt scrub fixtures/env/openai.env --map .safeprompt/session.json > /tmp/safeprompt-safe.env
cat /tmp/safeprompt-safe.env
```

Expected:

```txt
OPENAI_API_KEY=[OPENAI_KEY_1]
DATABASE_PASSWORD=[ENV_SECRET_1]
```

Command:

```bash
sed 's/OPENAI_API_KEY/FIXED_OPENAI_API_KEY/' /tmp/safeprompt-safe.env > /tmp/safeprompt-ai-output.env
safeprompt restore /tmp/safeprompt-ai-output.env --map .safeprompt/session.json
```

Expected:

```txt
FIXED_OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
DATABASE_PASSWORD=super-secret-password
```

## Closing Line

```txt
SafePrompt is local, no telemetry by default, and only redacts high-confidence secrets unless you ask for strict mode.
```

