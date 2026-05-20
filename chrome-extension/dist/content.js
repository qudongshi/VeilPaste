(function () {
  try {
    initVeilPasteContentScript();
  } catch (error) {
    console.error("[VeilPaste] content script failed to initialize", error);
  }

  function initVeilPasteContentScript() {
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
  const sharedRuleMetadata = {
    BEARER_TOKEN: {
      severity: "critical",
      title_zh: "Bearer 访问令牌",
      risk_zh: "会泄漏账号或服务访问权限。",
      title_en: "Bearer access token",
      risk_en: "May leak account or service access.",
    },
    BASIC_AUTH: {
      severity: "critical",
      title_zh: "Basic Authorization 凭证",
      risk_zh: "会泄漏用户名密码或等价凭证。",
      title_en: "Basic Authorization credential",
      risk_en: "May leak username/password or equivalent credentials.",
    },
    API_KEY_HEADER: {
      severity: "critical",
      title_zh: "API key 请求头",
      risk_zh: "会泄漏接口调用密钥。",
      title_en: "API key header",
      risk_en: "May leak an API access key.",
    },
    COOKIE: {
      severity: "critical",
      title_zh: "Cookie 会话值",
      risk_zh: "会泄漏登录会话或身份状态。",
      title_en: "Cookie session value",
      risk_en: "May leak login session or identity state.",
    },
    OPENAI_KEY: {
      severity: "critical",
      title_zh: "OpenAI Key",
      risk_zh: "会泄漏 AI 服务访问额度或项目权限。",
      title_en: "OpenAI key",
      risk_en: "May leak AI service quota or project access.",
    },
    AWS_KEY: {
      severity: "critical",
      title_zh: "AWS Access Key",
      risk_zh: "会泄漏云资源访问权限。",
      title_en: "AWS Access Key",
      risk_en: "May leak cloud resource access.",
    },
    GITHUB_TOKEN: {
      severity: "critical",
      title_zh: "GitHub Token",
      risk_zh: "会泄漏代码仓库或自动化权限。",
      title_en: "GitHub token",
      risk_en: "May leak repository or automation access.",
    },
    STRIPE_KEY: {
      severity: "critical",
      title_zh: "Stripe Key",
      risk_zh: "会泄漏支付服务访问权限。",
      title_en: "Stripe key",
      risk_en: "May leak payment service access.",
    },
    DATABASE_URL: {
      severity: "critical",
      title_zh: "数据库连接串",
      risk_zh: "会泄漏服务地址、账号或密码。",
      title_en: "Database connection string",
      risk_en: "May leak service host, username, or password.",
    },
    REDIS_URL: {
      severity: "critical",
      title_zh: "Redis 连接串",
      risk_zh: "会泄漏服务地址、账号或密码。",
      title_en: "Redis connection string",
      risk_en: "May leak service host, username, or password.",
    },
    MONGO_URI: {
      severity: "critical",
      title_zh: "MongoDB 连接串",
      risk_zh: "会泄漏服务地址、账号或密码。",
      title_en: "MongoDB connection string",
      risk_en: "May leak service host, username, or password.",
    },
    SENTRY_DSN: {
      severity: "warning",
      title_zh: "Sentry DSN",
      risk_zh: "可能暴露项目上报入口。",
      title_en: "Sentry DSN",
      risk_en: "May expose a project event ingestion endpoint.",
    },
    WEBHOOK_URL: {
      severity: "critical",
      title_zh: "Webhook 地址",
      risk_zh: "会泄漏可直接触发外部服务的地址。",
      title_en: "Webhook URL",
      risk_en: "May leak an endpoint that can trigger an external service.",
    },
    URL_USERINFO: {
      severity: "critical",
      title_zh: "URL 用户名密码",
      risk_zh: "会泄漏嵌在 URL 里的账号密码。",
      title_en: "URL username/password",
      risk_en: "May leak credentials embedded in a URL.",
    },
    PEM_PRIVATE_KEY: {
      severity: "critical",
      title_zh: "PEM 私钥",
      risk_zh: "会泄漏可用于签名或登录的私钥。",
      title_en: "PEM private key",
      risk_en: "May leak a private key used for signing or login.",
    },
    NPM_TOKEN: {
      severity: "critical",
      title_zh: "npm token",
      risk_zh: "会泄漏包发布或镜像仓库凭证。",
      title_en: "npm token",
      risk_en: "May leak package publishing or registry credentials.",
    },
    PYPIRC_SECRET: {
      severity: "critical",
      title_zh: "PyPI 凭证",
      risk_zh: "会泄漏包发布或镜像仓库凭证。",
      title_en: "PyPI credential",
      risk_en: "May leak package publishing or registry credentials.",
    },
    DOCKER_AUTH: {
      severity: "critical",
      title_zh: "Docker auth 凭证",
      risk_zh: "会泄漏包发布或镜像仓库凭证。",
      title_en: "Docker auth credential",
      risk_en: "May leak package publishing or registry credentials.",
    },
    URL_TOKEN: {
      severity: "critical",
      title_zh: "URL 参数中的敏感值",
      risk_zh: "会泄漏请求里的密钥或访问口令。",
      title_en: "Sensitive URL parameter",
      risk_en: "May leak keys or access tokens from the request.",
    },
  };
  const messages = {
    zh: {
      panelTitle: "发现可能泄漏的信息，已暂停粘贴。",
      explanation: "你可以先脱敏，再继续粘贴。",
      plainPaste: "不脱敏，继续粘贴",
      redactOnce: "本次脱敏",
      alwaysRedact: "以后自动脱敏",
      critical: "严重",
      warning: "提醒",
      settings: "设置",
      settingsTitle: "了解 VeilPaste",
      fallbackRisk: "可能包含不应发送给 AI 的敏感值。",
      toastAutomatic: "VeilPaste 已自动脱敏",
      toastDone: "VeilPaste 已完成脱敏",
      handled: "已处理：",
      moreHandled(count) {
        return `另有 ${count} 项风险已处理`;
      },
      safePasted: "已粘贴脱敏后的文本。",
      close: "关闭",
      closeAria: "关闭提示",
    },
    en: {
      panelTitle: "Possible leak found. Paste paused.",
      explanation:
        "You can redact first, then continue pasting.",
      plainPaste: "Paste without redaction",
      redactOnce: "Redact once",
      alwaysRedact: "Always redact",
      critical: "Critical",
      warning: "Notice",
      settings: "Settings",
      settingsTitle: "Learn about VeilPaste",
      fallbackRisk: "May contain sensitive values that should not be sent to AI.",
      toastAutomatic: "VeilPaste automatically redacted the paste",
      toastDone: "VeilPaste redacted the paste",
      handled: "Handled:",
      moreHandled(count) {
        return `${count} more risks handled`;
      },
      safePasted: "Redacted text was pasted.",
      close: "Close",
      closeAria: "Close notification",
    },
  };
  const redactionCounts = new Map();
  const autoRedactKeys = new Set();
  let autoRedactEnabled = false;

  globalThis.chrome?.storage?.local?.get({ autoRedactEnabled: false }, (settings) => {
    autoRedactEnabled = settings.autoRedactEnabled === true;
  });
  globalThis.chrome?.storage?.local?.onChanged?.addListener((changes) => {
    if (changes.autoRedactEnabled) {
      autoRedactEnabled = changes.autoRedactEnabled.newValue === true;
    }
  });

  document.addEventListener(
    "paste",
    (event) => {
      try {
        const text = event.clipboardData?.getData("text/plain") ?? "";
        const result = detectAndRedact(text);
        if (result.findings.length === 0) {
          return;
        }

        const target = event.target;
        if (!(target instanceof HTMLElement)) {
          return;
        }

        event.preventDefault();
        const decisionKey = buildDecisionKey(text, result.findings);
        if (autoRedactEnabled && autoRedactKeys.has(decisionKey)) {
          replaceTargetText(target, result.text);
          showRedactionCompleteToast(text, result.findings, true);
          return;
        }

        const redactionCount = redactionCounts.get(decisionKey) ?? 0;
        showVeilPastePanel({
          inputText: text,
          findings: result.findings,
          redactedText: result.text,
          showAlwaysRedact: autoRedactEnabled && redactionCount > 0,
          onPlainPaste: () => replaceTargetText(target, text),
          onRedactOnce: () => {
            redactionCounts.set(decisionKey, redactionCount + 1);
            replaceTargetText(target, result.text);
            showRedactionCompleteToast(text, result.findings, false);
          },
          onAlwaysRedact: () => {
            redactionCounts.set(decisionKey, redactionCount + 1);
            autoRedactKeys.add(decisionKey);
            replaceTargetText(target, result.text);
            showRedactionCompleteToast(text, result.findings, false);
          },
        });
      } catch (error) {
        console.error("[VeilPaste] paste handling failed", error);
      }
    },
    true,
  );

  function detectAndRedact(input) {
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

  function buildDecisionKey(inputText, findings) {
    const origin = globalThis.location?.origin ?? "unknown-origin";
    const fingerprint = findings
      .map((finding) => `${finding.kind}:${riskFieldName(inputText, finding)}`)
      .sort()
      .join("|");
    return `${origin}::${fingerprint}`;
  }

  function riskFieldName(inputText, finding) {
    const prefix = inputText.slice(0, finding.start);
    if (finding.kind === "URL_TOKEN") {
      return prefix.match(/[?&]([^=&\s'"`)\]}<>,]+)=$/i)?.[1] ?? "";
    }
    if (finding.kind === "COOKIE") {
      return prefix.match(/(?:^|[;\s])([^=;\s]+)=$/i)?.[1] ?? "";
    }
    if (finding.kind === "API_KEY_HEADER") {
      return lineForFinding(inputText, finding).match(/^\s*([^:\n]+)\s*:/)?.[1] ?? "";
    }
    return "";
  }

  function lineForFinding(inputText, finding) {
    const lineStart = inputText.lastIndexOf("\n", finding.start - 1) + 1;
    const nextLine = inputText.indexOf("\n", finding.end);
    const lineEnd = nextLine === -1 ? inputText.length : nextLine;
    return inputText.slice(lineStart, lineEnd);
  }

  function showVeilPastePanel({
    inputText,
    findings,
    showAlwaysRedact,
    onPlainPaste,
    onRedactOnce,
    onAlwaysRedact,
  }) {
    document.getElementById("veilpaste-panel")?.remove();
    const locale = currentLocale();
    const copy = messages[locale];

    const panel = document.createElement("div");
    panel.id = "veilpaste-panel";
    panel.style.cssText = [
      "position:fixed",
      "right:20px",
      "bottom:20px",
      "z-index:2147483647",
      "width:min(400px, calc(100vw - 40px))",
      "padding:16px",
      "border:1px solid #d8cdbb",
      "border-radius:18px",
      "background:linear-gradient(145deg,#fffdf7,#fff8ee)",
      "color:#111827",
      "font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif",
      "box-shadow:0 24px 70px rgba(100,73,36,.20)",
    ].join(";");

    const header = document.createElement("div");
    header.style.cssText = [
      "display:flex",
      "align-items:center",
      "justify-content:space-between",
      "gap:10px",
    ].join(";");

    const title = document.createElement("strong");
    title.textContent = copy.panelTitle;
    title.style.cssText = "font-size:18px;letter-spacing:-.02em";

    const infoButton = createInfoButton();
    infoButton.addEventListener("click", () => {
      openVeilPasteOptions();
    });
    header.append(title, infoButton);

    const explanation = document.createElement("p");
    explanation.style.cssText = "margin:10px 0 14px;color:#334155";
    explanation.textContent = copy.explanation;

    const riskList = document.createElement("div");
    riskList.style.cssText = "display:grid;gap:10px;margin:0 0 16px";
    for (const risk of riskItems(inputText, findings, locale)) {
      riskList.append(createRiskRow(risk, locale));
    }

    const plainButton = createPanelButton(copy.plainPaste);
    const redactOnceButton = createPanelButton(copy.redactOnce, true);
    const alwaysRedactButton = createPanelButton(copy.alwaysRedact, true);
    const buttonRow = document.createElement("div");
    buttonRow.style.cssText = [
      "display:flex",
      "gap:8px",
      "flex-wrap:wrap",
      "align-items:center",
      "justify-content:flex-end",
    ].join(";");
    buttonRow.append(plainButton, redactOnceButton);
    if (showAlwaysRedact) {
      buttonRow.append(alwaysRedactButton);
    }

    panel.append(header, explanation, riskList, buttonRow);

    plainButton.addEventListener("click", () => {
      try {
        onPlainPaste();
        panel.remove();
      } catch (error) {
        console.error("[VeilPaste] plain paste action failed", error);
      }
    });
    redactOnceButton.addEventListener("click", () => {
      try {
        onRedactOnce();
        panel.remove();
      } catch (error) {
        console.error("[VeilPaste] redact once action failed", error);
      }
    });
    alwaysRedactButton.addEventListener("click", () => {
      try {
        onAlwaysRedact();
        panel.remove();
      } catch (error) {
        console.error("[VeilPaste] always redact action failed", error);
      }
    });

    document.documentElement.append(panel);
  }

  function createRiskRow(risk, locale) {
    const copy = messages[locale];
    const row = document.createElement("div");
    row.style.cssText = [
      "display:grid",
      "grid-template-columns:auto 1fr",
      "gap:12px",
      "align-items:center",
      "padding:12px 14px",
      "border-radius:14px",
      `background:${risk.level === "critical" ? "#fef2f2" : "#fff7ed"}`,
      `border:1px solid ${risk.level === "critical" ? "#fecaca" : "#fed7aa"}`,
    ].join(";");

    const badge = document.createElement("span");
    badge.textContent = risk.level === "critical" ? copy.critical : copy.warning;
    badge.style.cssText = [
      "display:inline-flex",
      "align-items:center",
      "border-radius:999px",
      "padding:3px 8px",
      "font-size:12px",
      "font-weight:700",
      `background:${risk.level === "critical" ? "#dc2626" : "#f97316"}`,
      "color:#fff",
    ].join(";");

    const body = document.createElement("div");
    const name = document.createElement("div");
    name.textContent = risk.title;
    name.style.cssText = "font-size:15px;font-weight:800;letter-spacing:-.01em";
    const detail = document.createElement("div");
    detail.textContent = risk.detail;
    detail.style.cssText = "margin-top:2px;color:#475569";
    body.append(name, detail);

    row.append(badge, body);
    return row;
  }

  function riskItems(inputText, findings, locale = currentLocale()) {
    const seen = new Set();
    const risks = [];
    for (const finding of findings) {
      const risk = riskItem(inputText, finding, locale);
      const key = `${risk.level}:${risk.title}:${risk.detail}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      risks.push(risk);
    }
    return risks.sort((a, b) => riskRank(a.level) - riskRank(b.level));
  }

  function riskRank(level) {
    return level === "critical" ? 0 : 1;
  }

  function riskItem(inputText, finding, locale) {
    const field = riskFieldName(inputText, finding);
    const rule = sharedRuleMetadata[finding.kind];
    if (!rule) {
      return {
        level: "warning",
        title: finding.kind,
        detail: messages[locale].fallbackRisk,
      };
    }
    const title = locale === "zh" ? rule.title_zh : rule.title_en;
    return {
      level: rule.severity,
      title: riskTitleWithField(title, finding.kind, field, locale),
      detail: locale === "zh" ? rule.risk_zh : rule.risk_en,
    };
  }

  function riskTitleWithField(title, kind, field, locale) {
    if (!field) {
      return title;
    }
    if (kind === "URL_TOKEN") {
      return locale === "zh" ? `URL 参数 ${field}` : `URL parameter ${field}`;
    }
    if (kind === "COOKIE") {
      return `Cookie ${field}`;
    }
    if (kind === "API_KEY_HEADER") {
      return locale === "zh" ? `${field} 请求头` : `${field} header`;
    }
    return title;
  }

  function currentLocale() {
    const language =
      globalThis.navigator?.language ?? globalThis.navigator?.languages?.[0] ?? "en";
    return language.toLowerCase().startsWith("zh") ? "zh" : "en";
  }

  function showRedactionCompleteToast(inputText, findings, automatic) {
    document.getElementById("veilpaste-toast")?.remove();
    const locale = currentLocale();
    const copy = messages[locale];

    const toast = document.createElement("div");
    toast.id = "veilpaste-toast";
    toast.style.cssText = [
      "position:fixed",
      "right:20px",
      "bottom:20px",
      "z-index:2147483647",
      "width:min(340px, calc(100vw - 40px))",
      "padding:14px",
      "border:1px solid #bbf7d0",
      "border-radius:16px",
      "background:linear-gradient(145deg,#f0fdf4,#ffffff)",
      "color:#102018",
      "font:13px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif",
      "box-shadow:0 20px 60px rgba(22,101,52,.18)",
    ].join(";");

    const title = document.createElement("strong");
    title.textContent = automatic ? copy.toastAutomatic : copy.toastDone;
    title.style.cssText = "display:block;margin:0 0 7px;font-size:15px";

    const label = document.createElement("div");
    label.textContent = copy.handled;
    label.style.cssText = "margin:0 0 5px;color:#166534;font-weight:800";

    const list = document.createElement("ul");
    list.style.cssText = "margin:0 0 8px;padding-left:17px";
    const risks = riskItems(inputText, findings, locale);
    for (const risk of risks.slice(0, 3)) {
      const item = document.createElement("li");
      item.textContent = risk.title;
      list.append(item);
    }
    if (risks.length > 3) {
      const item = document.createElement("li");
      item.textContent = copy.moreHandled(risks.length - 3);
      list.append(item);
    }

    const detail = document.createElement("p");
    detail.textContent = copy.safePasted;
    detail.style.cssText = "margin:0;color:#475569";

    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.textContent = copy.close;
    closeButton.setAttribute("aria-label", copy.closeAria);
    closeButton.style.cssText = [
      "position:absolute",
      "top:10px",
      "right:10px",
      "border:0",
      "background:transparent",
      "color:#64748b",
      "font:700 12px/1 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif",
      "cursor:pointer",
    ].join(";");

    toast.append(title, label, list, detail, closeButton);
    document.documentElement.append(toast);

    const timer = setTimeout(() => {
      toast.remove();
    }, 4000);
    closeButton.addEventListener("click", () => {
      clearTimeout(timer);
      toast.remove();
    });
  }

  function createPanelButton(label, primary = false) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.style.cssText = [
      "appearance:none",
      `border:1px solid ${primary ? "#f97316" : "#d7c8b5"}`,
      "border-radius:10px",
      `background:${primary ? "#fff7ed" : "#ffffff"}`,
      `color:${primary ? "#c2410c" : "#334155"}`,
      "padding:8px 12px",
      "font:inherit",
      `font-weight:${primary ? "800" : "600"}`,
      "cursor:pointer",
    ].join(";");
    return button;
  }

  function createInfoButton() {
    const copy = messages[currentLocale()];
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = copy.settings;
    button.title = copy.settingsTitle;
    button.setAttribute("aria-label", copy.settingsTitle);
    button.style.cssText = [
      "appearance:none",
      "display:inline-flex",
      "align-items:center",
      "justify-content:center",
      "height:30px",
      "padding:0 9px",
      "border:1px solid #cbd5e1",
      "border-radius:999px",
      "background:#ffffffcc",
      "color:#334155",
      "font:700 12px/1 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif",
      "cursor:pointer",
    ].join(";");
    return button;
  }

  function openVeilPasteOptions() {
    const runtime = globalThis.chrome?.runtime;
    if (!runtime) {
      console.error("[VeilPaste] chrome.runtime is unavailable");
      return;
    }
    if (typeof runtime.sendMessage !== "function") {
      console.error("[VeilPaste] chrome.runtime.sendMessage is unavailable");
      return;
    }
    runtime.sendMessage({ type: "VEILPASTE_OPEN_OPTIONS" }, (response) => {
      if (runtime.lastError) {
        console.error("[VeilPaste] open options message failed", runtime.lastError.message);
        return;
      }
      if (response?.ok === false) {
        console.error("[VeilPaste] background failed to open options", response.error);
      }
    });
  }

  function replaceTargetText(target, value) {
    if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
      target.value = value;
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
      return;
    }

    if (target.isContentEditable) {
      target.textContent = value;
      target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
    }
  }

  }
})();

//# sourceURL=veilpaste-content-script.js
