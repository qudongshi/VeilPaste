const PANEL_ID = "veilpaste-panel";
const sharedRuleMetadata = {
  BEARER_TOKEN: {
    severity: "critical",
    title_zh: "Bearer 访问令牌",
    risk_zh: "会泄漏账号或服务访问权限。",
  },
  BASIC_AUTH: {
    severity: "critical",
    title_zh: "Basic Authorization 凭证",
    risk_zh: "会泄漏用户名密码或等价凭证。",
  },
  API_KEY_HEADER: {
    severity: "critical",
    title_zh: "API key 请求头",
    risk_zh: "会泄漏接口调用密钥。",
  },
  COOKIE: {
    severity: "critical",
    title_zh: "Cookie 会话值",
    risk_zh: "会泄漏登录会话或身份状态。",
  },
  OPENAI_KEY: {
    severity: "critical",
    title_zh: "OpenAI Key",
    risk_zh: "会泄漏 AI 服务访问额度或项目权限。",
  },
  AWS_KEY: {
    severity: "critical",
    title_zh: "AWS Access Key",
    risk_zh: "会泄漏云资源访问权限。",
  },
  GITHUB_TOKEN: {
    severity: "critical",
    title_zh: "GitHub Token",
    risk_zh: "会泄漏代码仓库或自动化权限。",
  },
  STRIPE_KEY: {
    severity: "critical",
    title_zh: "Stripe Key",
    risk_zh: "会泄漏支付服务访问权限。",
  },
  DATABASE_URL: {
    severity: "critical",
    title_zh: "数据库连接串",
    risk_zh: "会泄漏服务地址、账号或密码。",
  },
  REDIS_URL: {
    severity: "critical",
    title_zh: "Redis 连接串",
    risk_zh: "会泄漏服务地址、账号或密码。",
  },
  MONGO_URI: {
    severity: "critical",
    title_zh: "MongoDB 连接串",
    risk_zh: "会泄漏服务地址、账号或密码。",
  },
  SENTRY_DSN: {
    severity: "warning",
    title_zh: "Sentry DSN",
    risk_zh: "可能暴露项目上报入口。",
  },
  WEBHOOK_URL: {
    severity: "critical",
    title_zh: "Webhook 地址",
    risk_zh: "会泄漏可直接触发外部服务的地址。",
  },
  URL_USERINFO: {
    severity: "critical",
    title_zh: "URL 用户名密码",
    risk_zh: "会泄漏嵌在 URL 里的账号密码。",
  },
  PEM_PRIVATE_KEY: {
    severity: "critical",
    title_zh: "PEM 私钥",
    risk_zh: "会泄漏可用于签名或登录的私钥。",
  },
  NPM_TOKEN: {
    severity: "critical",
    title_zh: "npm token",
    risk_zh: "会泄漏包发布或镜像仓库凭证。",
  },
  PYPIRC_SECRET: {
    severity: "critical",
    title_zh: "PyPI 凭证",
    risk_zh: "会泄漏包发布或镜像仓库凭证。",
  },
  DOCKER_AUTH: {
    severity: "critical",
    title_zh: "Docker auth 凭证",
    risk_zh: "会泄漏包发布或镜像仓库凭证。",
  },
  URL_TOKEN: {
    severity: "critical",
    title_zh: "URL 参数中的敏感值",
    risk_zh: "会泄漏请求里的密钥或访问口令。",
  },
};

export function showVeilPastePanel({
  inputText,
  findings,
  showAlwaysRedact,
  onPlainPaste,
  onRedactOnce,
  onAlwaysRedact,
}) {
  document.getElementById(PANEL_ID)?.remove();

  const panel = document.createElement("div");
  panel.id = PANEL_ID;
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
  title.textContent = "VeilPaste 已暂停粘贴";
  title.style.cssText = "font-size:18px;letter-spacing:-.02em";

  const infoButton = createInfoButton();
  infoButton.addEventListener("click", () => {
    openVeilPasteOptions();
  });
  header.append(title, infoButton);

  const explanation = document.createElement("p");
  explanation.style.cssText = "margin:10px 0 14px;color:#334155";
  explanation.textContent =
    "VeilPaste 可在粘贴前协助脱敏，避免泄漏密钥、会话或访问令牌等敏感信息。";

  const riskList = document.createElement("div");
  riskList.style.cssText = "display:grid;gap:10px;margin:0 0 16px";
  for (const risk of riskItems(inputText, findings)) {
    riskList.append(createRiskRow(risk));
  }

  const plainButton = createPanelButton("不脱敏，继续粘贴");
  const redactOnceButton = createPanelButton("本次脱敏", true);
  const alwaysRedactButton = createPanelButton("以后自动脱敏", true);
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
    onPlainPaste();
    panel.remove();
  });
  redactOnceButton.addEventListener("click", () => {
    onRedactOnce();
    panel.remove();
  });
  alwaysRedactButton.addEventListener("click", () => {
    onAlwaysRedact();
    panel.remove();
  });

  document.documentElement.append(panel);
}

function createRiskRow(risk) {
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
  badge.textContent = risk.level === "critical" ? "严重" : "提醒";
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

function riskItems(inputText, findings) {
  const seen = new Set();
  const risks = [];
  for (const finding of findings) {
    const risk = riskItem(inputText, finding);
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

function riskItem(inputText, finding) {
  const field = riskFieldName(inputText, finding);
  const rule = sharedRuleMetadata[finding.kind];
  if (!rule) {
    return {
      level: "warning",
      title: finding.kind,
      detail: "可能包含不应发送给 AI 的敏感值。",
    };
  }
  return {
    level: rule.severity,
    title: riskTitleWithField(rule.title_zh, finding.kind, field),
    detail: rule.risk_zh,
  };
}

function riskTitleWithField(title, kind, field) {
  if (!field) {
    return title;
  }
  if (kind === "URL_TOKEN") {
    return `URL 参数 ${field}`;
  }
  if (kind === "COOKIE") {
    return `Cookie ${field}`;
  }
  if (kind === "API_KEY_HEADER") {
    return `${field} 请求头`;
  }
  return title;
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
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "设置";
  button.title = "了解 VeilPaste";
  button.setAttribute("aria-label", "了解 VeilPaste");
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

  const fallbackToBackground = () => {
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
  };

  if (typeof runtime.openOptionsPage === "function") {
    try {
      runtime.openOptionsPage(() => {
        if (runtime.lastError) {
          console.error("[VeilPaste] direct open options failed", runtime.lastError.message);
          fallbackToBackground();
        }
      });
      return;
    } catch (error) {
      console.error("[VeilPaste] direct open options threw", error);
    }
  }

  fallbackToBackground();
}
