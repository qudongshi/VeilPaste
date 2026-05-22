# VeilPaste Chrome Extension

This is a small developer utility for validating whether paste-time intervention can reduce AI-paste security risk.

It is intentionally limited to paste-time checks for obvious developer secrets.

## Scope

The prototype:

- Runs only on `https://chatgpt.com/*`, `https://claude.ai/*`, `https://www.perplexity.ai/*`, `https://www.doubao.com/*`, and `https://chat.qwen.ai/*`.
- Listens only to user `paste` events.
- Does not intercept submit/send/click actions.
- Does not scan the whole page.
- Does not make network requests.
- Does not collect telemetry.
- Persists only local extension settings.
- Does not persist pasted text, secret values, or risk memory.
- Does not implement restore or mapping.

## Behavior

When pasted text contains high-confidence developer secrets, VeilPaste pauses the paste and shows a local panel with:

- risk cards sorted by severity,
- `不脱敏，继续粘贴`,
- `本次脱敏`.

The extension does not rewrite the input until the user chooses a redaction action.

When `autoRedactEnabled` is on, VeilPaste redacts matching paste content immediately and shows a short completion toast instead of the confirmation panel.

The options page is a sidebar-style `VeilPaste 设置` page with:

- protected sites,
- built-in protection rules grouped by severity,
- redaction settings,
- privacy and storage boundaries,
- a local rule tester for fake sample text.

The local tester does not store input and does not make network requests.

Privacy boundary in user-facing terms: 不上传粘贴内容，不保存敏感值，不保存完整 prompt，不发网络请求。

## Permissions

`host_permissions` are limited to ChatGPT, Claude, Perplexity, Doubao, and Qwen because this prototype is only testing AI paste workflows.

`storage` 只保存 `autoRedactEnabled`, the local setting that controls whether matching paste content is redacted automatically without a confirmation panel. It does not store pasted text, secret values, or risk memory.

The background service worker only opens the extension options page when the paste panel `设置` button asks for it.

No clipboard permission is required because the prototype writes the selected target directly after a user action.

## Deferred Capabilities

The settings page intentionally shows some future directions without implementing them yet:

- Custom protected URLs are not implemented.
- User-defined rules are not implemented.
- Subscription rule packs, account login, sync, and team policy are not implemented.

Adding arbitrary sites later requires a separate permission-request and dynamic content-script design.

## Shared Vectors

The detector is checked against:

```txt
../fixtures/shared-vectors/p0-secrets.json
../fixtures/shared-vectors/false-positives.json
../fixtures/shared-contract/rules.json
```

Run:

```bash
npm test
```

The goal is shared behavior with the CLI through shared examples and a shared rule contract, not shared implementation.

The shared contract defines rule identity, severity, placeholder prefix, redaction span policy, and user-facing risk copy. Adding a rule requires updating the contract, shared vectors, Rust tests, and Chrome tests.

## Content Script Constraint

`manifest.json` loads `dist/content.js` as a classic content script. It must not contain top-level `import` or `export`.

`npm test` enforces this and also smoke-tests that the content script loads and handles a paste event without module runtime errors.

## Loading Locally

1. Open Chrome Extensions.
2. Enable Developer Mode.
3. Click `Load unpacked`.
4. Select this `chrome-extension/` directory.

Use only with fake test secrets while evaluating the prototype.

## Manual Options Page Test

1. Reload the unpacked extension from `chrome://extensions`.
2. Open the settings button from a paste warning panel.
3. Confirm the options page opens as `VeilPaste 设置`.
4. Confirm the default section is `脱敏设置`.
5. Open `保护网址` and confirm ChatGPT, Claude, Perplexity, Doubao, and Qwen are listed.
6. Open `保护规则` and confirm severe and warning rules are visible.
7. Open `测试区`, run the sample Bearer token test, and confirm the redacted output appears.
8. Confirm no network request is made from the options page.
