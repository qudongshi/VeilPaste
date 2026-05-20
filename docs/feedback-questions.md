# VeilPaste Trial Feedback Questions

Use fake or already-redacted examples only. Do not include production credentials, customer data, or live tokens in feedback.

## Context

1. Which AI tools do you paste developer context into most often?
2. Is your pasted context mostly English, 中文, or mixed?
3. Are you testing the CLI, the Chrome extension, or both?

## CLI

1. Did the CLI fit any workflow you already have, such as logs, `.env`, curl, or config files?
2. Was stdin/stdout usage understandable?
3. Did `--preview` help you decide whether to trust the output?
4. Would you need the local restore workflow, or is one-way redaction enough?
5. What fake sample did it miss or over-redact?

## Chrome

1. Were you willing to load the unpacked extension?
2. Did the paste warning appear at the right moment?
3. Was the explanation clear enough to know what risk was reduced?
4. Did `不脱敏，继续粘贴` / `本次脱敏` feel like the right choice set?
5. Did the settings page improve trust?
6. Did it feel annoying after repeated use?

## English / 中文

1. Which interface language would you prefer by default?
2. Did VeilPaste catch fake tokens inside English context?
3. Did VeilPaste catch fake tokens inside 中文 context?
4. Did it preserve surrounding Chinese explanation text?
5. Are English placeholder tokens such as `[BEARER_TOKEN_1]` understandable?

## Product Signal

1. Would you use VeilPaste again next week?
2. Would you prefer CLI-first, Chrome-first, or both?
3. Would you want support for Cursor, Codex, Claude Code, or another agent workflow?
4. What is the smallest change that would make this more useful?
