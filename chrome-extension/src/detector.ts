const rules = [
  {
    kind: "BEARER_TOKEN",
    regex: /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{8,})/gi,
    group: 1,
  },
  {
    kind: "BASIC_AUTH",
    regex: /Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})/gi,
    group: 1,
  },
  {
    kind: "API_KEY_HEADER",
    regex: /\b(?:X-Api-Key|X-Auth-Token|Api-Key)\s*[:：]\s*([A-Za-z0-9._~+/=:-]{8,})/gi,
    group: 1,
  },
  {
    kind: "COOKIE",
    regex: /\bCookie\s*:[^\n\r]*(?:^|[;\s])(?:[^=;\s]*(?:session|token|auth|secret)[^=;\s]*)=([^;\s'"`)\]}]+)/gi,
    group: 1,
  },
  {
    kind: "OPENAI_KEY",
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{10,})\b/g,
    group: 1,
  },
  {
    kind: "AWS_KEY",
    regex: /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
    group: 1,
  },
  {
    kind: "GITHUB_TOKEN",
    regex: /\b(gh[ps]_[A-Za-z0-9_]{10,})\b/g,
    group: 1,
  },
  {
    kind: "STRIPE_KEY",
    regex: /\b((?:sk_live|pk_live)_[A-Za-z0-9_]{10,})\b/g,
    group: 1,
  },
  {
    kind: "DATABASE_URL",
    regex: /\b(?:DATABASE_URL|POSTGRES_URL|MYSQL_URL)=((?:postgres|postgresql|mysql):\/\/[^\s'"`)\]}<>,]+)/g,
    group: 1,
  },
  {
    kind: "REDIS_URL",
    regex: /\bREDIS_URL=((?:redis|rediss):\/\/[^\s'"`)\]}<>,]+)/g,
    group: 1,
  },
  {
    kind: "MONGO_URI",
    regex: /\bMONGO_URI=(mongodb(?:\+srv)?:\/\/[^\s'"`)\]}<>,]+)/g,
    group: 1,
  },
  {
    kind: "SENTRY_DSN",
    regex: /\bSENTRY_DSN=(https:\/\/[^@\s'"`]+@[^/\s'"`]+\/[^\s'"`)\]}<>,]+)/g,
    group: 1,
  },
  {
    kind: "WEBHOOK_URL",
    regex: /\bWEBHOOK_URL=(https:\/\/(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks)\/[^\s'"`)\]}<>,]+)/g,
    group: 1,
  },
  {
    kind: "URL_USERINFO",
    regex: /https?:\/\/([^/\s'"`@]+:[^@\s'"`/]+)@/g,
    group: 1,
  },
  {
    kind: "PEM_PRIVATE_KEY",
    regex: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
    group: 1,
  },
  {
    kind: "NPM_TOKEN",
    regex: /_authToken\s*=\s*([^\s]+)/g,
    group: 1,
  },
  {
    kind: "PYPIRC_SECRET",
    regex: /^\s*(?:password|token)\s*=\s*([^\s]+)/gim,
    group: 1,
  },
  {
    kind: "DOCKER_AUTH",
    regex: /"auth"\s*:\s*"([^"]{8,})"/g,
    group: 1,
  },
  {
    kind: "URL_TOKEN",
    regex: /([?&])([A-Za-z0-9_-]*(?:token|key|secret|password)[A-Za-z0-9_-]*)=([^&\s'"`)\]}<>,]+)/gi,
    group: 3,
  },
];

export function detectAndRedact(input) {
  const findings = [];
  for (const rule of rules) {
    for (const match of input.matchAll(rule.regex)) {
      const original = match[rule.group];
      if (!original) {
        continue;
      }
      const offset = match[0].indexOf(original);
      if (offset < 0) {
        continue;
      }
      findings.push({
        kind: rule.kind,
        start: match.index + offset,
        end: match.index + offset + original.length,
        original,
      });
    }
  }

  const planned = planFindings(findings);
  const counts = new Map();
  for (const finding of planned) {
    const count = (counts.get(finding.kind) ?? 0) + 1;
    counts.set(finding.kind, count);
    finding.placeholder = `[${finding.kind}_${count}]`;
  }

  let text = input;
  for (const finding of [...planned].reverse()) {
    text = text.slice(0, finding.start) + finding.placeholder + text.slice(finding.end);
  }

  planned.sort((a, b) => a.start - b.start);
  return { text, findings: planned };
}

function planFindings(findings) {
  return findings
    .sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start))
    .reduce((planned, finding) => {
      if (planned.some((item) => finding.start < item.end && item.start < finding.end)) {
        return planned;
      }
      planned.push({ ...finding });
      return planned;
    }, []);
}
