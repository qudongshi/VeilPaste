# VeilPaste Shared Rule Contract

This contract defines shared rule identity, severity, placeholder prefix, redaction span policy, and user-facing risk copy for the CLI and Chrome runtimes.

It is not a detector implementation. Rust and Chrome may use different regex implementations, but both must pass the shared vectors and contract tests.

Adding a rule requires updating:

- `fixtures/shared-contract/rules.json`
- `fixtures/shared-vectors/p0-secrets.json` or false-positive vectors when behavior changes
- Rust contract tests
- Chrome contract tests
- Chrome risk UI metadata when the rule is user-visible
