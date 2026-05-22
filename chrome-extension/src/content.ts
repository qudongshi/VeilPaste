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
      explanation: "You can redact first, then continue pasting.",
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
  let autoRedactEnabled = false;
  let autoRedactLoaded = false;
  let autoRedactLoading = false;
  const autoRedactWaiters = [];

  loadAutoRedactSetting();
  globalThis.chrome?.storage?.local?.onChanged?.addListener((changes) => {
    if (changes.autoRedactEnabled) {
      autoRedactEnabled = changes.autoRedactEnabled.newValue === true;
      autoRedactLoaded = true;
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
        loadAutoRedactSetting((enabled) => {
          if (enabled) {
            replaceTargetText(target, result.text);
            showRedactionCompleteToast(text, result.findings, true);
            return;
          }

          showVeilPastePanel({
            inputText: text,
            findings: result.findings,
            redactedText: result.text,
            showAlwaysRedact: false,
            onPlainPaste: () => replaceTargetText(target, text),
            onRedactOnce: () => {
              replaceTargetText(target, result.text);
              showRedactionCompleteToast(text, result.findings, false);
            },
            onAlwaysRedact: () => {},
          });
        });
      } catch (error) {
        console.error("[VeilPaste] paste handling failed", error);
      }
    },
    true,
  );

  function loadAutoRedactSetting(callback = () => {}) {
    if (autoRedactLoaded) {
      callback(autoRedactEnabled);
      return;
    }

    autoRedactWaiters.push(callback);
    if (autoRedactLoading) {
      return;
    }
    autoRedactLoading = true;

    const storage = globalThis.chrome?.storage?.local;
    if (!storage?.get) {
      autoRedactLoaded = true;
      autoRedactLoading = false;
      flushAutoRedactWaiters();
      return;
    }

    storage.get({ autoRedactEnabled: false }, (settings) => {
      autoRedactEnabled = settings.autoRedactEnabled === true;
      autoRedactLoaded = true;
      autoRedactLoading = false;
      flushAutoRedactWaiters();
    });
  }

  function flushAutoRedactWaiters() {
    for (const callback of autoRedactWaiters.splice(0)) {
      callback(autoRedactEnabled);
    }
  }

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

  function showVeilPastePanel({
    inputText,
    findings,
    showAlwaysRedact,
    onPlainPaste,
    onRedactOnce,
    onAlwaysRedact,
  }) {
    document.getElementById("veilpaste-panel")?.remove();
    ensureVeilPasteStyles();
    const locale = currentLocale();
    const copy = messages[locale];

    const panel = document.createElement("div");
    panel.id = "veilpaste-panel";
    panel.className = "veil-prompt";

    const header = document.createElement("div");
    header.className = "veil-prompt-h";

    const statusIcon = document.createElement("span");
    statusIcon.className = "status";
    statusIcon.textContent = "!";

    const titleWrap = document.createElement("div");
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = copy.panelTitle;
    const explanation = document.createElement("div");
    explanation.className = "sub";
    explanation.textContent = copy.explanation;
    titleWrap.append(title, explanation);

    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "close";
    closeButton.textContent = "×";
    closeButton.setAttribute("aria-label", copy.closeAria);
    header.append(statusIcon, titleWrap, closeButton);

    const riskList = document.createElement("ul");
    riskList.className = "veil-risks";
    for (const risk of riskItems(inputText, findings, locale)) {
      riskList.append(createRiskRow(risk, locale));
    }

    const plainButton = createPanelButton(copy.plainPaste);
    const redactOnceButton = createPanelButton(copy.redactOnce, true);
    const alwaysRedactButton = createPanelButton(copy.alwaysRedact, false, "always");
    const buttonRow = document.createElement("div");
    buttonRow.className = "veil-actions";
    const firstRow = document.createElement("div");
    firstRow.className = "row";
    firstRow.append(plainButton, redactOnceButton);
    buttonRow.append(firstRow);
    if (showAlwaysRedact) {
      buttonRow.append(alwaysRedactButton);
    }

    const footer = document.createElement("div");
    footer.className = "veil-foot";
    const boundary = document.createElement("span");
    boundary.textContent = locale === "zh" ? "本地处理，不上传内容" : "Local processing. No upload.";
    const infoButton = createInfoButton();
    infoButton.addEventListener("click", () => {
      openVeilPasteOptions();
    });
    footer.append(boundary, infoButton);

    panel.append(header, riskList, buttonRow, footer);

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

    closeButton.addEventListener("click", () => {
      panel.remove();
    });
  }

  function createRiskRow(risk, locale) {
    const copy = messages[locale];
    const row = document.createElement("li");
    row.className = "veil-risk";

    const badge = document.createElement("span");
    badge.className = `badge ${risk.level === "critical" ? "crit" : "notice"}`;
    badge.textContent = risk.level === "critical" ? copy.critical : copy.warning;

    const head = document.createElement("div");
    head.className = "veil-risk-head";
    const name = document.createElement("div");
    name.className = "veil-risk-t";
    name.textContent = risk.title;
    head.append(badge, name);

    const detail = document.createElement("div");
    detail.className = "veil-risk-d";
    detail.textContent = risk.detail;

    row.append(head, detail);
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
    ensureVeilPasteStyles();
    const locale = currentLocale();
    const copy = messages[locale];

    const toast = document.createElement("div");
    toast.id = "veilpaste-toast";
    toast.className = "veil-toast";

    const header = document.createElement("div");
    header.className = "veil-toast-h";
    const check = document.createElement("span");
    check.className = "check";
    check.textContent = "✓";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = automatic ? copy.toastAutomatic : copy.toastDone;
    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "close";
    closeButton.textContent = "×";
    closeButton.setAttribute("aria-label", copy.closeAria);
    header.append(check, title, closeButton);

    const body = document.createElement("div");
    body.className = "body";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = copy.handled;

    const list = document.createElement("ul");
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
    body.append(label, list);

    const detail = document.createElement("p");
    detail.className = "veil-toast-foot";
    detail.textContent = copy.safePasted;

    const progress = document.createElement("div");
    progress.className = "veil-progress";

    toast.append(header, body, detail, progress);
    document.documentElement.append(toast);

    const timer = setTimeout(() => {
      toast.remove();
    }, 4000);
    closeButton.addEventListener("click", () => {
      clearTimeout(timer);
      toast.remove();
    });
  }

  function createPanelButton(label, primary = false, variant = "") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = variant
      ? `veil-btn ${variant}`
      : primary
        ? "veil-btn recommend"
        : "veil-btn subtle";
    button.textContent = label;
    return button;
  }

  function createInfoButton() {
    const copy = messages[currentLocale()];
    const button = document.createElement("button");
    button.type = "button";
    button.className = "gear";
    button.textContent = copy.settings;
    button.title = copy.settingsTitle;
    button.setAttribute("aria-label", copy.settingsTitle);
    return button;
  }

  function ensureVeilPasteStyles() {
    if (document.getElementById("veilpaste-style")) {
      return;
    }
    if (!document.head?.append) {
      return;
    }
    const style = document.createElement("style");
    style.id = "veilpaste-style";
    style.textContent = `
      :root {
        --vp-bg:#fbfbfa;
        --vp-surface:#ffffff;
        --vp-surface-2:#f6f5f3;
        --vp-ink:#14130f;
        --vp-ink-2:#4a4842;
        --vp-ink-3:#807d76;
        --vp-ink-4:#aeaaa3;
        --vp-line:#e8e6e2;
        --vp-line-strong:#d9d6d1;
        --vp-accent:#5b4fcf;
        --vp-accent-soft:color-mix(in oklab, var(--vp-accent) 8%, transparent);
        --vp-accent-line:color-mix(in oklab, var(--vp-accent) 22%, transparent);
        --vp-critical:#c8372d;
        --vp-critical-soft:#fdecea;
        --vp-notice:#b87100;
        --vp-notice-soft:#fbf2e0;
        --vp-ok:#2d7a5a;
        --vp-shadow-pop:0 1px 2px rgba(20,19,15,.05), 0 8px 22px rgba(20,19,15,.08), 0 24px 60px rgba(20,19,15,.10);
      }
      .veil-prompt,
      .veil-toast {
        position: fixed;
        right: 24px;
        bottom: 24px;
        z-index: 2147483647;
        color: var(--vp-ink);
        background: color-mix(in oklab, var(--vp-surface) 88%, transparent);
        backdrop-filter: saturate(1.4) blur(28px);
        -webkit-backdrop-filter: saturate(1.4) blur(28px);
        border: 1px solid color-mix(in oklab, var(--vp-ink) 9%, transparent);
        box-shadow: var(--vp-shadow-pop);
        font: 13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Helvetica,system-ui,sans-serif;
      }
      .veil-prompt {
        width: min(400px, calc(100vw - 40px));
        max-height: min(560px, calc(100vh - 48px));
        display: flex;
        flex-direction: column;
        border-radius: 14px;
        overflow: hidden;
      }
      .veil-prompt-h {
        display: grid;
        grid-template-columns: auto 1fr auto;
        align-items: start;
        gap: 10px;
        padding: 14px 14px 8px;
      }
      .veil-prompt-h .status,
      .veil-toast .check {
        width: 18px;
        height: 18px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        font-size: 11px;
        font-weight: 700;
      }
      .veil-prompt-h .status {
        color: var(--vp-notice);
        background: color-mix(in oklab, var(--vp-notice) 14%, transparent);
        margin-top: 1px;
      }
      .veil-prompt .title {
        font-size: 13px;
        font-weight: 600;
        letter-spacing: -.005em;
        line-height: 1.4;
      }
      .veil-prompt .sub {
        margin-top: 2px;
        color: var(--vp-ink-3);
        font-size: 12px;
        line-height: 1.45;
      }
      .veil-prompt-h .close {
        appearance: none;
        width: 22px;
        height: 22px;
        border: 0;
        border-radius: 6px;
        background: transparent;
        color: var(--vp-ink-3);
        cursor: default;
        font-size: 14px;
      }
      .veil-prompt-h .close:hover {
        background: color-mix(in oklab, var(--vp-ink) 6%, transparent);
        color: var(--vp-ink);
      }
      .veil-risks {
        margin: 0;
        padding: 2px 14px;
        list-style: none;
        display: flex;
        flex-direction: column;
        max-height: 248px;
        overflow-y: auto;
        scrollbar-width: thin;
        scrollbar-color: color-mix(in oklab, var(--vp-ink) 18%, transparent) transparent;
      }
      .veil-risks::-webkit-scrollbar { width: 6px; }
      .veil-risks::-webkit-scrollbar-thumb {
        background: color-mix(in oklab, var(--vp-ink) 18%, transparent);
        border-radius: 3px;
      }
      .veil-risk {
        display: block;
        padding: 8px 0;
        border-top: 1px solid color-mix(in oklab, var(--vp-ink) 6%, transparent);
      }
      .veil-risk:first-child { border-top: 0; }
      .veil-risk-head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .veil-risk-t {
        min-width: 0;
        color: var(--vp-ink);
        font-size: 12.5px;
        font-weight: 500;
        line-height: 1.35;
      }
      .veil-risk-d {
        margin-top: 3px;
        color: var(--vp-ink-3);
        font-size: 11.5px;
        line-height: 1.4;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 2px 7px 2px 6px;
        border: 1px solid transparent;
        border-radius: 4px;
        font-size: 10.5px;
        font-weight: 500;
        letter-spacing: .04em;
        text-transform: uppercase;
      }
      .badge::before {
        content: "";
        width: 5px;
        height: 5px;
        border-radius: 50%;
      }
      .badge.crit {
        color: var(--vp-critical);
        background: var(--vp-critical-soft);
        border-color: color-mix(in oklab, var(--vp-critical) 20%, transparent);
      }
      .badge.crit::before { background: var(--vp-critical); }
      .badge.notice {
        color: var(--vp-notice);
        background: var(--vp-notice-soft);
        border-color: color-mix(in oklab, var(--vp-notice) 20%, transparent);
      }
      .badge.notice::before { background: var(--vp-notice); }
      .veil-actions {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 12px 14px;
        border-top: 1px solid color-mix(in oklab, var(--vp-ink) 6%, transparent);
      }
      .veil-actions .row {
        display: flex;
        gap: 6px;
      }
      .veil-actions .row > * { flex: 1; }
      .veil-btn {
        appearance: none;
        border: 1px solid color-mix(in oklab, var(--vp-ink) 14%, transparent);
        border-radius: 8px;
        background: color-mix(in oklab, var(--vp-surface) 80%, transparent);
        color: var(--vp-ink);
        cursor: default;
        font: 500 12.5px/1.35 -apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Helvetica,system-ui,sans-serif;
        letter-spacing: -.003em;
        padding: 7px 10px;
      }
      .veil-btn.recommend {
        color: var(--vp-accent);
        background: var(--vp-accent-soft);
        border-color: var(--vp-accent-line);
      }
      .veil-btn.recommend:hover {
        background: color-mix(in oklab, var(--vp-accent) 14%, transparent);
      }
      .veil-btn.subtle {
        color: var(--vp-ink-2);
        background: transparent;
        border-color: color-mix(in oklab, var(--vp-ink) 10%, transparent);
      }
      .veil-btn.subtle:hover {
        background: color-mix(in oklab, var(--vp-ink) 4%, transparent);
        color: var(--vp-ink);
      }
      .veil-btn.always {
        color: var(--vp-ink-2);
        background: transparent;
        border-color: color-mix(in oklab, var(--vp-ink) 16%, transparent);
        border-style: dashed;
      }
      .veil-btn.always:hover {
        background: color-mix(in oklab, var(--vp-accent) 6%, transparent);
        border-color: var(--vp-accent-line);
        color: var(--vp-accent);
      }
      .gear {
        appearance: none;
        border: 0;
        border-radius: 5px;
        background: transparent;
        color: var(--vp-ink-3);
        cursor: default;
        display: inline-flex;
        align-items: center;
        gap: 5px;
        font: 500 11.5px/1 -apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Helvetica,system-ui,sans-serif;
        padding: 2px 6px;
      }
      .gear:hover {
        background: color-mix(in oklab, var(--vp-ink) 6%, transparent);
        color: var(--vp-ink);
      }
      .veil-foot {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 14px 12px;
        color: var(--vp-ink-3);
        font-size: 11px;
      }
      .veil-toast {
        width: min(340px, calc(100vw - 40px));
        background: color-mix(in oklab, var(--vp-surface) 90%, transparent);
        border-radius: 12px;
        overflow: hidden;
        animation: veilToastIn .28s cubic-bezier(.2,.7,.2,1) both;
      }
      @keyframes veilToastIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .veil-toast-h {
        display: grid;
        grid-template-columns: auto 1fr auto;
        align-items: center;
        gap: 10px;
        padding: 12px 12px 6px;
      }
      .veil-toast .check {
        color: var(--vp-ok);
        background: color-mix(in oklab, var(--vp-ok) 14%, transparent);
      }
      .veil-toast .title {
        min-width: 0;
        font-size: 12.5px;
        font-weight: 600;
        line-height: 1.35;
      }
      .veil-toast .close {
        appearance: none;
        width: 20px;
        height: 20px;
        border: 0;
        border-radius: 5px;
        background: transparent;
        color: var(--vp-ink-3);
        cursor: default;
        font-size: 13px;
      }
      .veil-toast .close:hover {
        background: color-mix(in oklab, var(--vp-ink) 6%, transparent);
        color: var(--vp-ink);
      }
      .veil-toast .body { padding: 0 12px 10px; }
      .veil-toast .label {
        margin-top: 2px;
        color: var(--vp-ink-3);
        font-size: 11px;
        letter-spacing: .02em;
      }
      .veil-toast ul {
        list-style: none;
        margin: 6px 0 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .veil-toast li {
        position: relative;
        padding-left: 14px;
        color: var(--vp-ink);
        font-size: 12px;
      }
      .veil-toast li::before {
        content: "";
        position: absolute;
        left: 0;
        top: 8px;
        width: 8px;
        height: 1px;
        background: var(--vp-ink-4);
      }
      .veil-toast-foot {
        margin: 0;
        padding: 8px 12px;
        border-top: 1px solid color-mix(in oklab, var(--vp-ink) 6%, transparent);
        color: var(--vp-ink-3);
        background: color-mix(in oklab, var(--vp-surface) 60%, transparent);
        font-size: 11.5px;
      }
      .veil-progress {
        position: relative;
        height: 2px;
        background: color-mix(in oklab, var(--vp-ink) 5%, transparent);
      }
      .veil-progress::after {
        content: "";
        position: absolute;
        inset: 0;
        right: 100%;
        background: color-mix(in oklab, var(--vp-ok) 60%, transparent);
        animation: veilProgress 4s linear forwards;
      }
      @keyframes veilProgress { to { right: 0%; } }
    `;
    document.head.append(style);
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
