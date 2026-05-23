const zh = {
  "title:index": "VeilPaste - 本地 AI 粘贴脱敏工具",
  "title:privacy": "VeilPaste 隐私政策",
  "title:support": "VeilPaste 支持",
  "description:index":
    "VeilPaste 在你把日志、curl、.env 或配置片段粘贴到 AI 网站前，本地识别明显的开发者密钥并协助脱敏。",
  "description:privacy":
    "VeilPaste 隐私政策：当前 Chrome 插件本地处理粘贴内容，不上传内容，不保存敏感值，不发网络请求。",
  "description:support": "VeilPaste 支持页面：反馈误报、漏报、安装问题和 Chrome 插件使用问题。",
  "nav.privacy": "隐私政策",
  "nav.support": "支持",
  "punctuation.period": "。",
  "home.eyebrow": "Local paste guard for AI workflows",
  "home.title": "在粘贴给 AI 之前，先本地发现明显的密钥风险。",
  "home.lede":
    "VeilPaste 是一个小型开发者工具。它在 ChatGPT、Claude、Perplexity、豆包和 Qwen 上监听用户主动粘贴的文本，发现明显的 API key、Bearer token、Cookie、数据库连接串或私钥片段后，先提示你选择是否脱敏。",
  "home.privacyCta": "查看隐私政策",
  "home.supportCta": "获取支持",
  "home.localTitle": "本地处理",
  "home.localBody": "检测与脱敏在浏览器本地完成。当前 Chrome 插件不上传粘贴内容，不保存敏感值，也不发网络请求。",
  "home.sitesTitle": "只在指定 AI 网站运行",
  "home.sitesBody": "当前保护范围限定为 ChatGPT、Claude、Perplexity、豆包和 Qwen，避免请求过宽的网站权限。",
  "home.pasteTitle": "只处理粘贴动作",
  "home.pasteBody": "插件只监听用户触发的 paste 事件，不扫描整个页面，不拦截发送、提交或点击动作。",
  "home.risksTitle": "当前可识别的常见风险",
  "home.risk1": "Authorization Bearer token 和 Basic Auth 凭证",
  "home.risk2": "OpenAI、AWS、GitHub、Stripe 等常见访问密钥",
  "home.risk3": "Cookie 会话值、URL 查询参数中的 token/key/secret/password",
  "home.risk4": "数据库 URL、Redis URL、MongoDB URI、Sentry DSN 和 webhook URL",
  "home.risk5": "PEM 私钥、npm token、pypirc 凭证、Docker registry auth",
  "home.boundaryTitle": "当前边界",
  "home.boundaryBody1":
    "VeilPaste 只能帮助发现明显的开发者密钥和凭证片段，不能保证一段 prompt 已经安全，也不能替代人工审查。处理真实生产数据前，请先确认你的团队安全要求。",
  "home.boundaryBody2": "当前公开版本不是账号或订阅产品，不包含团队管理、云端同步、遥测、远程规则包或付费授权逻辑。",
  "privacy.title": "VeilPaste 隐私政策",
  "privacy.updated": "最后更新：2026 年 5 月 23 日",
  "privacy.overviewTitle": "概述",
  "privacy.overviewBody":
    "VeilPaste 是一个本地 AI 粘贴脱敏工具。当前 Chrome 插件会在指定 AI 网站上监听用户主动触发的粘贴动作，本地识别明显的开发者密钥、访问令牌、会话值、连接串和私钥片段，并协助用户在粘贴前脱敏。",
  "privacy.noCollectTitle": "我们不收集的内容",
  "privacy.noCollect1": "不上传粘贴内容。",
  "privacy.noCollect2": "不保存敏感值、密钥、token、Cookie、连接串或私钥。",
  "privacy.noCollect3": "不保存完整 prompt。",
  "privacy.noCollect4": "不收集遥测、分析事件或使用统计。",
  "privacy.noCollect5": "当前 Chrome 插件不向 VeilPaste 服务器发起网络请求。",
  "privacy.localStorageTitle": "本地保存的信息",
  "privacy.localStorageBody":
    "VeilPaste 使用 Chrome 的本地扩展存储保存一个设置项：用户是否开启“以后自动脱敏”。该设置仅保存在用户本机浏览器中，用于决定后续检测到敏感信息时是否直接本地脱敏。",
  "privacy.sitesTitle": "运行的网站范围",
  "privacy.sitesBody": "当前 Chrome 插件只在以下网站运行：",
  "privacy.permissionsTitle": "权限用途",
  "privacy.permissionsBody":
    "storage 权限仅用于保存本地设置。网站访问权限仅用于在上述 AI 网站上检测用户主动粘贴的文本。VeilPaste 不使用这些权限读取浏览历史、扫描整页内容或拦截提交动作。",
  "privacy.thirdPartyTitle": "第三方服务",
  "privacy.thirdPartyBody":
    "当前 Chrome 插件不集成第三方分析、广告、支付、账号登录或订阅服务。未来如果新增账号、订阅或云端能力，本政策会在上线前更新，并明确说明新增的数据处理范围。",
  "privacy.controlTitle": "用户控制",
  "privacy.controlBody": "用户可以在插件设置页关闭自动脱敏，也可以通过 Chrome 扩展管理页停用或卸载 VeilPaste。卸载扩展会删除浏览器本地保存的扩展设置。",
  "privacy.contactTitle": "联系我们",
  "privacy.contactBody": "如果你对本隐私政策或 VeilPaste 的数据处理方式有问题，请联系：",
  "support.title": "VeilPaste 支持",
  "support.lede": "如果你遇到误报、漏报、安装问题或使用疑问，可以通过下面的方式反馈。",
  "support.emailTitle": "联系邮箱",
  "support.emailBody": "请发送邮件至",
  "support.feedbackTitle": "反馈误报或漏报",
  "support.feedbackBody": "为了保护你的安全，请不要发送真实密钥、真实 token、真实 Cookie 或生产连接串。建议提供：",
  "support.feedback1": "使用 fake secret 改写后的样例文本。",
  "support.feedback2": "你使用的网站，例如 ChatGPT、Claude、Perplexity、豆包或 Qwen。",
  "support.feedback3": "浏览器版本和 VeilPaste 版本。",
  "support.feedback4": "期望行为：应该提示、应该脱敏、还是不应该触发。",
  "support.sitesTitle": "当前支持的网站",
  "support.faqTitle": "常见问题",
  "support.faqUploadQ": "VeilPaste 会上传我的粘贴内容吗？",
  "support.faqUploadA": "不会。当前 Chrome 插件在本地处理粘贴文本，不上传内容，也不发网络请求。",
  "support.faqStoreQ": "VeilPaste 会保存我的密钥吗？",
  "support.faqStoreA": "不会。当前版本只保存“以后自动脱敏”这个本地设置，不保存敏感值或完整 prompt。",
  "support.faqSitesQ": "为什么只支持几个 AI 网站？",
  "support.faqSitesA": "这是为了减少网站权限范围。后续增加站点时，会继续按最小权限原则处理。",
  "support.faqSubscriptionQ": "当前版本包含订阅或账号功能吗？",
  "support.faqSubscriptionA": "不包含。当前公开版本不是账号或订阅产品，也没有云端同步或远程规则包。",
  "support.uninstallTitle": "卸载方式",
  "support.uninstallBody": "打开 Chrome 的扩展管理页，找到 VeilPaste，选择停用或移除即可。卸载扩展会删除浏览器本地保存的扩展设置。",
};

const en = {
  "title:index": "VeilPaste - Local AI Paste Redaction Helper",
  "title:privacy": "VeilPaste Privacy Policy",
  "title:support": "VeilPaste Support",
  "description:index":
    "VeilPaste locally detects obvious developer secrets before you paste logs, curl commands, .env files, or config snippets into AI websites.",
  "description:privacy":
    "VeilPaste privacy policy: the current Chrome extension processes paste content locally, does not upload content, does not store sensitive values, and does not make network requests.",
  "description:support": "VeilPaste support page for false positives, missed detections, install issues, and Chrome extension questions.",
  "nav.privacy": "Privacy",
  "nav.support": "Support",
  "punctuation.period": ".",
  "home.eyebrow": "Local paste guard for AI workflows",
  "home.title": "Find obvious secret risks locally before pasting into AI.",
  "home.lede":
    "VeilPaste is a small developer utility. On ChatGPT, Claude, Perplexity, Doubao, and Qwen, it listens for user-initiated paste events and warns before obvious API keys, Bearer tokens, cookies, database URLs, or private key snippets are pasted.",
  "home.privacyCta": "View privacy policy",
  "home.supportCta": "Get support",
  "home.localTitle": "Local processing",
  "home.localBody": "Detection and redaction happen locally in the browser. The current Chrome extension does not upload pasted content, store sensitive values, or make network requests.",
  "home.sitesTitle": "Limited AI site scope",
  "home.sitesBody": "The current protection scope is limited to ChatGPT, Claude, Perplexity, Doubao, and Qwen to avoid broad website permissions.",
  "home.pasteTitle": "Paste events only",
  "home.pasteBody": "The extension listens only to user-triggered paste events. It does not scan the whole page or intercept send, submit, or click actions.",
  "home.risksTitle": "Common risks currently detected",
  "home.risk1": "Authorization Bearer tokens and Basic Auth credentials",
  "home.risk2": "Common access keys such as OpenAI, AWS, GitHub, and Stripe keys",
  "home.risk3": "Cookie session values and URL token/key/secret/password parameters",
  "home.risk4": "Database URLs, Redis URLs, MongoDB URIs, Sentry DSNs, and webhook URLs",
  "home.risk5": "PEM private keys, npm tokens, pypirc credentials, and Docker registry auth",
  "home.boundaryTitle": "Current boundary",
  "home.boundaryBody1":
    "VeilPaste helps catch obvious developer secrets and credential snippets. It cannot guarantee that a prompt is safe, and it does not replace manual review. Confirm your team's security requirements before handling real production data.",
  "home.boundaryBody2": "The current public version is not an account or subscription product. It does not include team management, cloud sync, telemetry, remote rule packs, or paid licensing logic.",
  "privacy.title": "VeilPaste Privacy Policy",
  "privacy.updated": "Last updated: May 23, 2026",
  "privacy.overviewTitle": "Overview",
  "privacy.overviewBody":
    "VeilPaste is a local AI paste redaction helper. The current Chrome extension listens for user-initiated paste events on supported AI websites, locally detects obvious developer keys, access tokens, session values, connection strings, and private key snippets, and helps users redact them before pasting.",
  "privacy.noCollectTitle": "What we do not collect",
  "privacy.noCollect1": "We do not upload pasted content.",
  "privacy.noCollect2": "We do not store sensitive values, keys, tokens, cookies, connection strings, or private keys.",
  "privacy.noCollect3": "We do not store full prompts.",
  "privacy.noCollect4": "We do not collect telemetry, analytics events, or usage statistics.",
  "privacy.noCollect5": "The current Chrome extension does not make network requests to VeilPaste servers.",
  "privacy.localStorageTitle": "Information stored locally",
  "privacy.localStorageBody":
    "VeilPaste uses Chrome extension local storage to save one setting: whether the user has enabled Always redact. This setting is stored only in the user's local browser and controls whether matching sensitive content is redacted automatically.",
  "privacy.sitesTitle": "Website scope",
  "privacy.sitesBody": "The current Chrome extension runs only on these websites:",
  "privacy.permissionsTitle": "Permission use",
  "privacy.permissionsBody":
    "The storage permission is used only to save local settings. Website permissions are used only to detect user-initiated paste content on the supported AI websites above. VeilPaste does not use these permissions to read browsing history, scan full pages, or intercept submit actions.",
  "privacy.thirdPartyTitle": "Third-party services",
  "privacy.thirdPartyBody":
    "The current Chrome extension does not integrate third-party analytics, advertising, payment, account login, or subscription services. If account, subscription, or cloud features are added in the future, this policy will be updated before launch and will describe the new data handling scope.",
  "privacy.controlTitle": "User control",
  "privacy.controlBody": "Users can turn off automatic redaction in the extension settings page, or disable or remove VeilPaste from Chrome's extension management page. Removing the extension deletes locally stored extension settings.",
  "privacy.contactTitle": "Contact us",
  "privacy.contactBody": "If you have questions about this privacy policy or VeilPaste data handling, contact:",
  "support.title": "VeilPaste Support",
  "support.lede": "If you run into false positives, missed detections, install issues, or usage questions, contact us below.",
  "support.emailTitle": "Support email",
  "support.emailBody": "Email",
  "support.feedbackTitle": "Report a false positive or missed detection",
  "support.feedbackBody": "For your safety, do not send real keys, real tokens, real cookies, or production connection strings. Please provide:",
  "support.feedback1": "A sample rewritten with fake secrets.",
  "support.feedback2": "The website you used, such as ChatGPT, Claude, Perplexity, Doubao, or Qwen.",
  "support.feedback3": "Your browser version and VeilPaste version.",
  "support.feedback4": "The expected behavior: should warn, should redact, or should not trigger.",
  "support.sitesTitle": "Currently supported websites",
  "support.faqTitle": "FAQ",
  "support.faqUploadQ": "Does VeilPaste upload my pasted content?",
  "support.faqUploadA": "No. The current Chrome extension processes pasted text locally, does not upload content, and does not make network requests.",
  "support.faqStoreQ": "Does VeilPaste store my secrets?",
  "support.faqStoreA": "No. The current version only stores the local Always redact setting. It does not store sensitive values or full prompts.",
  "support.faqSitesQ": "Why are only a few AI websites supported?",
  "support.faqSitesA": "This keeps website permissions narrow. Future site additions will continue to follow the least-permission principle.",
  "support.faqSubscriptionQ": "Does the current version include subscription or account features?",
  "support.faqSubscriptionA": "No. The current public version is not an account or subscription product and has no cloud sync or remote rule packs.",
  "support.uninstallTitle": "Uninstall",
  "support.uninstallBody": "Open Chrome's extension management page, find VeilPaste, then disable or remove it. Removing the extension deletes locally stored extension settings.",
};

const dictionaries = { zh, en };

function currentLocale() {
  const languages = navigator.languages?.length ? navigator.languages : [navigator.language || "zh-CN"];
  return languages[0].toLowerCase().startsWith("zh") ? "zh" : "en";
}

function currentPage() {
  const filename = location.pathname.split("/").pop() || "index.html";
  if (filename === "privacy.html") return "privacy";
  if (filename === "support.html") return "support";
  return "index";
}

function applyI18n() {
  const locale = currentLocale();
  const page = currentPage();
  const copy = dictionaries[locale];
  document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
  document.title = copy[`title:${page}`];

  const description = document.querySelector('[data-i18n-meta="description"]');
  if (description) {
    description.setAttribute("content", copy[`description:${page}`]);
  }

  for (const element of document.querySelectorAll("[data-i18n]")) {
    const value = copy[element.getAttribute("data-i18n")];
    if (value) {
      element.textContent = value;
    }
  }
}

applyI18n();
