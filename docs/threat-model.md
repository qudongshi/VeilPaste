# VeilPaste Threat Model

VeilPaste is a small developer utility for reducing AI-paste security risk by catching known high-confidence developer secrets before paste. It does not guarantee that scrubbed content is safe to send to an external AI service.

## VeilPaste V0 Defends Against

- Accidentally pasting known secret formats into AI tools.
- Sending `.env`, curl, HTTP headers, logs, or config snippets with high-confidence tokens.
- Losing local usability after redaction by using reversible placeholders and a local mapping file.

## VeilPaste V0 Does Not Guarantee

- Detecting every possible secret.
- Detecting all PII.
- Detecting every URL, DSN, config, or webhook format.
- Detecting semantic secrets such as internal project names or customer names.
- Protecting mapping files from malicious local processes.
- Preserving semantic correctness during restore.
- Preventing a user from manually copying unsanitized content.

## Mapping File Risk

Mapping files contain original secrets. Treat them as live secret material.

VeilPaste writes mapping metadata (`session_id`, `created_at`) and restricts mapping file permissions on Unix-like systems. This reduces accidental exposure but does not protect against malicious local processes running as the same user.

Do not commit files such as:

```txt
.veilpaste/session.json
```

Recommended `.gitignore` entry:

```gitignore
.veilpaste/
```

## Operational Guidance

- Use `veilpaste scrub --preview` before first use on a new input type.
- Check [known misses](known-misses.md) before relying on a new input type.
- Use `veilpaste map inspect --map <path>` to inspect placeholders and kinds without printing original secret values.
- Use `--strict` only when you accept more false positives.
- Use `--quiet` for clipboard and shell pipelines.
- Manually review high-sensitivity content after scrubbing.
- Rotate secrets if you believe they were already sent to an external AI service.
