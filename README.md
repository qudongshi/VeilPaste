# SafePrompt

```txt
Paste safely into AI.
```

SafePrompt is a local CLI airlock for developer context. It scrubs high-confidence secrets from logs, curl commands, `.env` files, headers, and config snippets before you paste them into ChatGPT, Claude, Codex, or other AI tools.

## Why

Developers routinely paste debugging context into AI:

- production logs
- curl requests
- `.env` files
- stack traces
- HTTP headers

Those snippets often contain API keys, Bearer tokens, JWTs, cookies, and URL secrets. Manual deletion is fragile.

## Quick Demo

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | safeprompt
```

Output:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

Clipboard workflow:

```bash
pbpaste | safeprompt --quiet | pbcopy
```

Preview workflow:

```bash
safeprompt scrub fixtures/curl/request.curl --preview
```

Full walkthrough: [docs/usage-guide.md](docs/usage-guide.md).
Recording script: [docs/demo-script.md](docs/demo-script.md).

## Reversible Redaction

```bash
safeprompt scrub .env --map .safeprompt/session.json > safe.env
```

Example scrub:

```txt
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
```

becomes:

```txt
OPENAI_API_KEY=[OPENAI_KEY_1]
```

If AI returns an edited file containing `[OPENAI_KEY_1]`, restore locally:

```bash
safeprompt restore ai-output.env --map .safeprompt/session.json
```

## Commands

```bash
safeprompt < input.txt
safeprompt scrub input.txt
safeprompt scrub input.txt --map .safeprompt/session.json
safeprompt scrub input.txt --preview
safeprompt scrub input.txt --strict
safeprompt --quiet < input.txt
safeprompt restore output.txt --map .safeprompt/session.json
safeprompt check input.txt
safeprompt explain input.txt
```

Use `--quiet` for pipelines where stdout must contain only scrubbed content.

## Install From This Checkout

```bash
scripts/install.sh
```

Equivalent command:

```bash
cargo install --path crates/safeprompt-cli
```

## Release Checks

```bash
cargo fmt --all --check
cargo test
cargo build --release
safeprompt --version
```

## V0 Detection Scope

SafePrompt V0 defaults to high-confidence secrets only:

- Bearer token
- JWT
- Cookie values
- OpenAI keys
- AWS access keys
- GitHub `ghp_` / `ghs_` tokens
- Stripe `sk_live_` / `pk_live_` keys
- `.env` secret values
- URL query secrets such as `token`, `api_key`, `secret`, `password`

SafePrompt does not redact these by default:

- email
- phone number
- normal IP address
- person name
- internal project name
- ordinary UUID

## Trust Guarantees

- No network calls by default.
- No telemetry by default.
- No account required.
- Inputs are processed locally.
- Mapping files stay local.

If you write a mapping under `.safeprompt/` inside a git repo and the directory is not ignored, SafePrompt warns:

```txt
WARNING: mapping file contains original secrets. Do not commit it. Add .safeprompt/ to .gitignore.
```

Read [docs/threat-model.md](docs/threat-model.md) before using SafePrompt with highly sensitive data.

## Warning

SafePrompt is a first line of defense, not a complete firewall. Review highly sensitive content manually before sending it to any AI system.
