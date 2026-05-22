# VeilPaste Trial Guide

VeilPaste is a small developer utility to reduce AI-paste security risk. It catches obvious developer secrets and sensitive config values before they are pasted into AI tools.

This trial is for 10-20 developers. Use fake or already-redacted examples during feedback. Do not send production secrets, private customer data, or live credentials.

## What To Try

### CLI

Use the CLI when you have logs, `.env` files, curl commands, headers, or config snippets.

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste
```

Expected output:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

Try preview mode when you want to see what would be changed:

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

Use mapping only for local restore workflows:

```bash
veilpaste scrub .env --map .veilpaste/session.json > redacted.env
veilpaste restore ai-output.env --map .veilpaste/session.json
```

Mapping files contain originals and must stay local.

### Chrome Paste Guard

Use the Chrome extension when pasting into ChatGPT, Claude, Perplexity, Doubao, or Qwen.

1. Open `chrome://extensions`.
2. Enable Developer Mode.
3. Click `Load unpacked`.
4. Select `chrome-extension/`.
5. Refresh the target AI page.
6. Paste a fake Bearer token, cookie, URL token, or config snippet.

The extension should pause the paste, explain what it found, and let you choose whether to paste as-is or redact for this paste.

## Current Boundaries

- Detection runs locally.
- No telemetry is collected.
- No prompt, secret, or risk fingerprint is uploaded.
- Chrome risk memory is session-only.
- `autoRedactEnabled` is the only persistent Chrome setting.
- Placeholder tokens stay in English and machine-readable.
- English and Chinese UI/context support is for beta usability, not broad language classification.

## What Feedback Matters

- Did you understand what VeilPaste was doing?
- Did the CLI or Chrome entry point feel more natural?
- Did any warning feel too noisy?
- Did it miss an obvious fake token in English or Chinese surrounding text?
- Did it alter safe surrounding text?
- Would you use it again during AI-assisted debugging?
