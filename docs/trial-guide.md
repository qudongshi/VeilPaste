# VeilPaste Trial Guide

VeilPaste helps you paste developer text into AI with less risk. It catches obvious keys, tokens, cookies, private keys, and connection strings before they are sent.

This trial is for 10-20 developers. Use fake or already-redacted examples. Do not use production secrets, private customer data, or live credentials.

## What To Try

### CLI

Use the CLI for logs, `.env` files, curl commands, headers, and config snippets.

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste
```

Expected output:

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

Preview changes before redacting:

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

Restore only when you need a local editing workflow:

```bash
veilpaste scrub .env --map .veilpaste/session.json > redacted.env
veilpaste restore ai-output.env --map .veilpaste/session.json
```

The map contains original values. Keep it local.

### Chrome Extension

Use the extension when pasting into ChatGPT, Claude, Perplexity, Doubao, or Qwen.

1. Open `chrome://extensions`.
2. Enable Developer Mode.
3. Click `Load unpacked`.
4. Select `chrome-extension/`.
5. Refresh the AI page.
6. Paste fake text that contains a Bearer token, cookie, URL token, or config secret.

VeilPaste should pause the paste, show what it found, and let you choose whether to paste as-is or redact first.

## Current Boundaries

- Detection runs locally.
- No telemetry is collected.
- No prompt or secret is uploaded.
- Temporary choices reset after refresh.
- The only saved setting is whether “Always redact” is enabled.
- English and Chinese UI support is for usability, not broad language detection.

## What Feedback Matters

- Did you understand what VeilPaste was doing?
- Did the CLI or Chrome entry point feel more natural?
- Did any warning feel too noisy?
- Did it miss an obvious fake token in English or Chinese surrounding text?
- Did it change safe surrounding text?
- Would you use it again during AI-assisted debugging?
