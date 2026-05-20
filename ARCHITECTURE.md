# VeilPaste Architecture

VeilPaste is a small local developer utility with two entry points:

- CLI for trusted local workflows over files, stdin/stdout, mapping, restore, preview, and check.
- Chrome paste guard for paste-time intervention on selected AI sites.

The two runtimes do not yet share detector implementation. They share a rule contract and test vectors.

## Shared Contract

`fixtures/shared-contract/rules.json` is the source of truth for:

- `kind`: Chrome-facing detector kind.
- `rust_kind`: Rust `SecretKind` debug name.
- `placeholder_prefix`: placeholder family such as `BEARER_TOKEN`.
- `severity`: `critical` or `warning`.
- `redaction_span`: intended redaction unit.
- `title_zh` / `risk_zh` and `title_en` / `risk_en`: user-facing risk copy for Chinese and non-Chinese Chrome UI.

`fixtures/shared-vectors/` is the executable behavior gate. Rust and Chrome may use different regex implementations, but both must pass the same shared vectors and contract tests.

## Rule Change Policy

Any new detector rule must update:

- `fixtures/shared-contract/rules.json`
- `fixtures/shared-vectors/p0-secrets.json` or false-positive vectors when behavior changes
- Rust contract tests
- Chrome contract tests
- Chrome risk UI metadata when user-visible

Do not add broad PII or business-context rules without explicit false-positive fixtures and a product decision. Current beta scope is obvious developer secrets and sensitive config values that commonly appear before AI paste.

## Chrome Boundary

The Chrome extension is paste-only. It does not intercept submit/send/click actions, does not scan the whole page, and does not make network requests.

`autoRedactEnabled` may be stored in `chrome.storage.local`. Risk memory stays session-only and is scoped by origin.

## Future WASM Gate

Rust-to-WASM detector sharing can be reconsidered only after Chrome paste-time use has clear beta signal, contract drift becomes costly, and the extension build/release pipeline is stable enough to absorb WASM packaging and debugging complexity.
