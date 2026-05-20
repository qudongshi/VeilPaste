import { detectAndRedact } from "./detector.js";

const messages = {
  zh: {
    "nav.overview": "总览",
    "nav.sites": "保护网址",
    "nav.rules": "保护规则",
    "nav.redaction": "脱敏设置",
    "nav.privacy": "隐私与存储",
    "nav.tester": "测试区",
    "overview.title": "VeilPaste",
    "overview.body":
      "粘贴前先检查，发现敏感信息就提醒你脱敏。",
    "overview.metricSites": "当前保护网址",
    "overview.metricRules": "内置保护规则",
    "overview.metricNetwork": "网络请求",
    "overview.metricLocalValue": "本地",
    "overview.metricLocal": "检测与脱敏",
    "sites.title": "保护网址",
    "sites.body": "VeilPaste 只在这些 AI 网站检查粘贴内容。",
    "status.enabled": "已启用",
    "status.disabled": "未启用",
    "sites.customTitle": "自定义网址",
    "sites.customBody": "当前不能自己添加网址。后续会单独设计这个能力。",
    "rules.title": "保护规则",
    "rules.body": "这些是当前内置启用的高置信规则。当前不支持自定义规则。",
    "rules.critical": "严重",
    "rules.warning": "提醒",
    "rules.enabled": "内置启用",
    "rules.openaiRisk": "会泄漏 AI 服务访问额度或项目权限。",
    "rules.bearerTitle": "Bearer 访问令牌",
    "rules.bearerRisk": "会泄漏账号或服务访问权限。",
    "rules.cookieTitle": "Cookie sessionid",
    "rules.cookieRisk": "会泄漏登录会话或身份状态。",
    "rules.urlTokenTitle": "URL 参数 token/api_key",
    "rules.urlTokenRisk": "会泄漏请求里的密钥、访问口令或临时凭证。",
    "rules.providerKeyRisk": "会泄漏代码仓库、云资源或支付服务访问权限。",
    "rules.databaseTitle": "数据库 URL / PEM 私钥",
    "rules.databaseRisk": "会泄漏数据库连接信息或私钥材料。",
    "rules.sentryRisk": "可能暴露项目上报入口。",
    "rules.webhookRisk": "可能暴露 Slack、Discord 等 webhook 投递入口。",
    "rules.basicAuthTitle": "URL userinfo / Basic Auth",
    "rules.basicAuthRisk": "可能把用户名、密码或基础认证值带入 AI。",
    "rules.packageAuthTitle": "npm / pypirc / Docker registry auth",
    "rules.packageAuthRisk": "可能泄漏包管理器或镜像仓库认证信息。",
    "redaction.title": "脱敏设置",
    "redaction.body": "设置发现敏感信息后的处理方式。",
    "redaction.autoTitle": "启用“以后自动脱敏”",
    "redaction.autoBody": "开启后才显示“以后自动脱敏”。记录按网站隔离，刷新页面后失效。",
    "privacy.title": "隐私与存储",
    "privacy.body": "VeilPaste 的默认边界是本地处理、最小存储。",
    "privacy.noUpload": "不上传粘贴内容",
    "privacy.noSecrets": "不保存敏感值",
    "privacy.noPrompt": "不保存完整 prompt",
    "privacy.noNetwork": "不发网络请求",
    "privacy.remember": "只记住你是否开启“以后自动脱敏”。",
    "privacy.background": "设置页只在你点击设置时打开。",
    "privacy.hosts": "只在 ChatGPT、Claude、Perplexity、豆包和 Qwen 上工作。",
    "privacy.session": "临时记录刷新页面后失效。",
    "tester.title": "测试区",
    "tester.body": "粘贴一段假数据进行本地测试，查看 VeilPaste 会识别哪些规则。内容只在本页面本地处理。",
    "tester.run": "本地测试",
    "tester.findingsTitle": "检测结果",
    "tester.outputTitle": "脱敏后结果",
    "tester.noFindings": "未检测到内置规则命中的敏感信息。",
    "tester.error": "本地检测失败，请刷新页面后重试。",
  },
  en: {
    "nav.overview": "Overview",
    "nav.sites": "Protected sites",
    "nav.rules": "Protection rules",
    "nav.redaction": "Redaction settings",
    "nav.privacy": "Privacy & storage",
    "nav.tester": "Local test",
    "overview.title": "VeilPaste",
    "overview.body":
      "Checks before paste and helps redact sensitive information before it reaches AI.",
    "overview.metricSites": "Protected sites",
    "overview.metricRules": "Built-in rules",
    "overview.metricNetwork": "Network requests",
    "overview.metricLocalValue": "Local",
    "overview.metricLocal": "Detection and redaction",
    "sites.title": "Protected sites",
    "sites.body": "VeilPaste only checks pasted text on these AI sites.",
    "status.enabled": "Enabled",
    "status.disabled": "Disabled",
    "sites.customTitle": "Custom sites",
    "sites.customBody": "Custom sites are not available yet. This will be designed separately.",
    "rules.title": "Protection rules",
    "rules.body": "These high-confidence built-in rules are enabled today. Custom rules are not supported yet.",
    "rules.critical": "Critical",
    "rules.warning": "Notice",
    "rules.enabled": "Built in",
    "rules.openaiRisk": "May leak AI service quota or project access.",
    "rules.bearerTitle": "Bearer access token",
    "rules.bearerRisk": "May leak account or service access.",
    "rules.cookieTitle": "Cookie sessionid",
    "rules.cookieRisk": "May leak login session or identity state.",
    "rules.urlTokenTitle": "URL parameter token/api_key",
    "rules.urlTokenRisk": "May leak request keys, access tokens, or temporary credentials.",
    "rules.providerKeyRisk": "May leak repository, cloud, or payment service access.",
    "rules.databaseTitle": "Database URL / PEM private key",
    "rules.databaseRisk": "May leak database connection details or private key material.",
    "rules.sentryRisk": "May expose a project reporting endpoint.",
    "rules.webhookRisk": "May expose Slack, Discord, or other webhook delivery endpoints.",
    "rules.basicAuthTitle": "URL userinfo / Basic Auth",
    "rules.basicAuthRisk": "May send usernames, passwords, or basic auth values to AI.",
    "rules.packageAuthTitle": "npm / pypirc / Docker registry auth",
    "rules.packageAuthRisk": "May leak package manager or registry credentials.",
    "redaction.title": "Redaction settings",
    "redaction.body": "Choose what happens after sensitive information is found.",
    "redaction.autoTitle": "Enable “Always redact”",
    "redaction.autoBody": "Only shows “Always redact” after this is enabled. Records are isolated by site and expire after refresh.",
    "privacy.title": "Privacy & storage",
    "privacy.body": "VeilPaste defaults to local processing and minimal storage.",
    "privacy.noUpload": "Does not upload pasted content",
    "privacy.noSecrets": "Does not store sensitive values",
    "privacy.noPrompt": "Does not store the full prompt",
    "privacy.noNetwork": "Does not make network requests",
    "privacy.remember": "Only remembers whether “Always redact” is enabled.",
    "privacy.background": "The settings page opens only when you click Settings.",
    "privacy.hosts": "Works only on ChatGPT, Claude, Perplexity, Doubao, and Qwen.",
    "privacy.session": "Temporary records expire after refresh.",
    "tester.title": "Local test",
    "tester.body": "Paste fake sample text to test locally and see which rules VeilPaste detects. Content is processed only on this page.",
    "tester.run": "Run local test",
    "tester.findingsTitle": "Findings",
    "tester.outputTitle": "Redacted output",
    "tester.noFindings": "No sensitive information matched built-in rules.",
    "tester.error": "Local detection failed. Refresh this page and try again.",
  },
};

function currentLocale() {
  const locale =
    navigator.languages?.find((language) => language) ?? navigator.language ?? "en";
  return locale.toLowerCase().startsWith("zh") ? "zh" : "en";
}

const locale = currentLocale();
const copy = messages[locale];

const autoRedactInput = document.getElementById("autoRedactEnabled");
const testerInput = document.getElementById("ruleTesterInput");
const testerRun = document.getElementById("ruleTesterRun");
const testerFindings = document.getElementById("ruleTesterFindings");
const testerOutput = document.getElementById("ruleTesterOutput");
const navItems = Array.from(document.querySelectorAll(".nav-item"));
const sections = Array.from(document.querySelectorAll(".page-section"));

applyI18n();

chrome.storage.local.get({ autoRedactEnabled: false }, (settings) => {
  autoRedactInput.checked = settings.autoRedactEnabled === true;
});

autoRedactInput.addEventListener("change", () => {
  chrome.storage.local.set({ autoRedactEnabled: autoRedactInput.checked });
});

for (const item of navItems) {
  item.addEventListener("click", () => {
    const target = item.getAttribute("data-target");
    for (const navItem of navItems) {
      navItem.classList.toggle("is-active", navItem === item);
    }
    for (const section of sections) {
      const isActive = section.dataset.section === target;
      section.hidden = !isActive;
      section.classList.toggle("is-active", isActive);
    }
  });
}

testerRun.addEventListener("click", () => {
  try {
    const result = detectAndRedact(testerInput.value);
    renderTesterResult(result);
  } catch (error) {
    console.error("[VeilPaste] options detector failed", error);
    testerFindings.textContent = copy["tester.error"];
    testerOutput.textContent = "";
  }
});

function applyI18n() {
  document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
  document.title = locale === "zh" ? "VeilPaste 设置" : "VeilPaste Settings";
  for (const element of document.querySelectorAll("[data-i18n]")) {
    const key = element.getAttribute("data-i18n");
    if (key && copy[key]) {
      element.textContent = copy[key];
    }
  }
}

function renderTesterResult(result) {
  testerFindings.replaceChildren();
  if (result.findings.length === 0) {
    testerFindings.textContent = copy["tester.noFindings"];
    testerOutput.textContent = result.text;
    return;
  }

  const list = document.createElement("ul");
  for (const finding of result.findings) {
    const item = document.createElement("li");
    item.textContent = finding.kind;
    list.append(item);
  }
  testerFindings.append(list);
  testerOutput.textContent = result.text;
}
