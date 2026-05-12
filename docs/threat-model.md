# VeilPaste Threat Model

## VeilPaste V0 Defends Against

- Accidentally pasting known secret formats into AI tools.
- Sending `.env`, curl, HTTP headers, logs, or config snippets with high-confidence tokens.
- Losing local usability after redaction by using reversible placeholders and a local mapping file.

## VeilPaste V0 Does Not Guarantee

- Detecting every possible secret.
- Detecting all PII.
- Detecting semantic secrets such as internal project names or customer names.
- Protecting mapping files from malicious local processes.
- Preventing a user from manually copying unsanitized content.

## Mapping File Risk

Mapping files contain original secrets.

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
- Use `--strict` only when you accept more false positives.
- Use `--quiet` for clipboard and shell pipelines.
- Manually review high-sensitivity content after scrubbing.
- Rotate secrets if you believe they were already sent to an external AI service.
