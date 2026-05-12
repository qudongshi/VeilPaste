# VeilPaste

```txt
Paste safely into AI.
```

VeilPaste is a local CLI airlock for developer context. It scrubs high-confidence secrets from logs, curl commands, `.env` files, headers, and config snippets before you paste them into ChatGPT, Claude, Codex, or other AI tools.

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
Recording script: [docs/demo-script.md](docs/demo-script.md).

## Reversible Redaction

```bash
veilpaste scrub .env --map .veilpaste/session.json > safe.env
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
veilpaste restore ai-output.env --map .veilpaste/session.json
```

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

Use `--quiet` for pipelines where stdout must contain only scrubbed content.

## Install From This Checkout

```bash
scripts/install.sh
```

Equivalent command:

```bash
cargo install --path crates/veilpaste-cli
```

## Release Checks

```bash
cargo fmt --all --check
cargo test
cargo build --release
veilpaste --version
```

## V0 Detection Scope

VeilPaste V0 defaults to high-confidence secrets only:

- Bearer token
- JWT
- Cookie values
- OpenAI keys
- AWS access keys
- GitHub `ghp_` / `ghs_` tokens
- Stripe `sk_live_` / `pk_live_` keys
- `.env` secret values
- URL query secrets such as `token`, `api_key`, `secret`, `password`

VeilPaste does not redact these by default:

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

If you write a mapping under `.veilpaste/` inside a git repo and the directory is not ignored, VeilPaste warns:

```txt
WARNING: mapping file contains original secrets. Do not commit it. Add .veilpaste/ to .gitignore.
```

Read [docs/threat-model.md](docs/threat-model.md) before using VeilPaste with highly sensitive data.

## Warning

VeilPaste is a first line of defense, not a complete firewall. Review highly sensitive content manually before sending it to any AI system.
