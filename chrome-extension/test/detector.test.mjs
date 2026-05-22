import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { detectAndRedact } from "../dist/detector.js";

const root = path.resolve(import.meta.dirname, "../..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function readContractRules() {
  const contract = readJson("fixtures/shared-contract/rules.json");
  return new Map(contract.rules.map((rule) => [rule.kind, rule]));
}

function assertSharedContractSchemaAllowsCurrentRules() {
  const contract = readJson("fixtures/shared-contract/rules.json");
  const schema = readJson("fixtures/shared-contract/schema.json");
  const required = new Set(schema.properties.rules.items.required);
  const properties = new Set(Object.keys(schema.properties.rules.items.properties));

  for (const field of ["title_en", "risk_en"]) {
    assert.ok(required.has(field), `schema should require ${field}`);
    assert.ok(properties.has(field), `schema should define ${field}`);
  }

  for (const rule of contract.rules) {
    for (const key of Object.keys(rule)) {
      assert.ok(properties.has(key), `schema should allow ${key}`);
    }
  }
}

test("detector matches shared P0 secret vectors", () => {
  const vectors = readJson("fixtures/shared-vectors/p0-secrets.json");
  const vectorNames = new Set(vectors.map((vector) => vector.name));

  assert.ok(vectorNames.has("chinese context with bearer token"));
  assert.ok(vectorNames.has("english context with database url"));
  assert.ok(vectorNames.has("mixed markdown context with cookie"));
  assert.ok(vectorNames.has("fullwidth colon api key header"));

  for (const vector of vectors) {
    const result = detectAndRedact(vector.input);
    for (const expected of vector.expect_contains) {
      assert.ok(
        result.text.includes(expected),
        `${vector.name} should contain ${expected}; got:\n${result.text}`,
      );
    }
    for (const forbidden of vector.expect_not_contains) {
      assert.ok(
        !result.text.includes(forbidden),
        `${vector.name} should not contain ${forbidden}; got:\n${result.text}`,
      );
    }
  }
});

test("detector leaves shared false-positive vectors unchanged", () => {
  const vectors = readJson("fixtures/shared-vectors/false-positives.json");

  for (const vector of vectors) {
    const result = detectAndRedact(vector.input);
    assert.equal(result.text, vector.input, vector.name);
    assert.equal(result.findings.length, 0, vector.name);
  }
});

test("manifest-loaded content scripts are classic scripts", () => {
  const manifest = readJson("chrome-extension/manifest.json");
  assert.equal(manifest.options_page, "help.html");
  assert.equal(manifest.background.service_worker, "dist/background.js");
  assert.ok(manifest.permissions.includes("storage"));
  for (const host of [
    "https://chatgpt.com/*",
    "https://claude.ai/*",
    "https://www.perplexity.ai/*",
    "https://www.doubao.com/*",
    "https://chat.qwen.ai/*",
  ]) {
    assert.ok(manifest.host_permissions.includes(host), `${host} should be permitted`);
    assert.ok(
      manifest.content_scripts.some((script) => (script.matches ?? []).includes(host)),
      `${host} should load the content script`,
    );
  }

  for (const contentScript of manifest.content_scripts ?? []) {
    for (const scriptPath of contentScript.js ?? []) {
      const script = fs.readFileSync(path.join(root, "chrome-extension", scriptPath), "utf8");
      assert.doesNotMatch(script, /^\s*import\s/m, `${scriptPath} must not use import`);
      assert.doesNotMatch(script, /^\s*export\s/m, `${scriptPath} must not use export`);
    }
  }
});

test("chrome package exposes reproducible build and check scripts", () => {
  const packageJson = readJson("chrome-extension/package.json");

  assert.equal(packageJson.scripts.build, "node scripts/build.mjs");
  assert.equal(packageJson.scripts["check:package"], "node scripts/check-package.mjs");
  assert.equal(
    packageJson.scripts.check,
    "node scripts/check-contract.mjs && npm run build && node scripts/check-package.mjs && npm test",
  );
});

test("chrome detector findings comply with shared rule contract", () => {
  const rules = readContractRules();
  const vectors = readJson("fixtures/shared-vectors/p0-secrets.json");

  for (const vector of vectors) {
    const result = detectAndRedact(vector.input);

    for (const finding of result.findings) {
      const rule = rules.get(finding.kind);
      assert.ok(rule, `${vector.name}: missing contract for ${finding.kind}`);
      assert.ok(
        finding.placeholder.startsWith(`[${rule.placeholder_prefix}_`),
        `${vector.name}: placeholder ${finding.placeholder} does not match ${rule.placeholder_prefix}`,
      );
    }
  }
});

test("chrome risk copy is backed by shared rule contract", () => {
  const rules = readContractRules();
  const contentScript = fs.readFileSync(path.join(root, "chrome-extension/dist/content.js"), "utf8");
  const expectedKinds = [
    "URL_TOKEN",
    "BEARER_TOKEN",
    "BASIC_AUTH",
    "API_KEY_HEADER",
    "COOKIE",
    "DATABASE_URL",
    "REDIS_URL",
    "MONGO_URI",
    "PEM_PRIVATE_KEY",
    "URL_USERINFO",
    "WEBHOOK_URL",
    "SENTRY_DSN",
    "NPM_TOKEN",
    "PYPIRC_SECRET",
    "DOCKER_AUTH",
  ];

  for (const kind of expectedKinds) {
    const rule = rules.get(kind);
    assert.ok(rule, `missing contract for Chrome risk kind ${kind}`);
    assert.ok(rule.title_en, `missing English title for ${kind}`);
    assert.ok(rule.risk_en, `missing English risk copy for ${kind}`);
    assert.match(contentScript, new RegExp(`${kind}:[\\s\\S]*title_zh`));
    assert.match(contentScript, new RegExp(`${kind}:[\\s\\S]*risk_zh`));
    assert.match(contentScript, new RegExp(`${kind}:[\\s\\S]*title_en`));
    assert.match(contentScript, new RegExp(`${kind}:[\\s\\S]*risk_en`));
    assert.match(contentScript, new RegExp(escapeRegExp(rule.title_en)));
    assert.match(contentScript, new RegExp(escapeRegExp(rule.risk_en)));
  }
});

test("shared contract schema matches current rule fields", () => {
  assertSharedContractSchemaAllowsCurrentRules();
});

test("trial readiness docs use small utility positioning", () => {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const chromeReadme = fs.readFileSync(path.join(root, "chrome-extension/README.md"), "utf8");
  const trialGuide = fs.readFileSync(path.join(root, "docs/trial-guide.md"), "utf8");
  const feedbackQuestions = fs.readFileSync(
    path.join(root, "docs/feedback-questions.md"),
    "utf8",
  );
  const chineseReadme = fs.readFileSync(path.join(root, "README.zh-CN.md"), "utf8");

  for (const text of [readme, chromeReadme, trialGuide]) {
    assert.match(text, /small developer utility|小而美/);
    assert.match(text, /reduce AI-paste security risk|降低.*安全风险/);
    assert.doesNotMatch(text, /security product|security tool|安全产品|安全工具/);
  }

  assert.match(trialGuide, /10-20/);
  assert.match(trialGuide, /fake|脱敏/);
  assert.match(feedbackQuestions, /CLI/);
  assert.match(feedbackQuestions, /Chrome/);
  assert.match(feedbackQuestions, /中文|English/);
  assert.doesNotMatch(feedbackQuestions, /真实 secret|真实密钥/);
  assert.match(chineseReadme, /小而美/);
  assert.match(chineseReadme, /降低.*安全风险/);
  assert.match(chineseReadme, /试用/);
});

test("options page keeps scrolling inside the content area and uses roomier navigation", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /\.app-shell\s*{[\s\S]*height:\s*min\(720px,\s*calc\(100vh - 56px\)\)/);
  assert.match(help, /\.main-card\s*{[\s\S]*overflow-y:\s*auto/);
  assert.match(help, /\.nav-item\s*{[\s\S]*padding:\s*10px 12px/);
  assert.doesNotMatch(help, /\.app-shell\s*{[\s\S]*min-height:\s*720px/);
});

test("options page uses the packaged logo and scrolls only the rules list", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /src="icons\/veilpaste_64\.png"/);
  assert.doesNotMatch(help, /class="brand-mark"/);
  assert.match(help, /class="rules-scroll"/);
  assert.match(help, /\.rules-scroll\s*{[\s\S]*overflow-y:\s*auto/);
  assert.match(help, /内置脱敏规则。当前不支持自定义规则。/);
  assert.doesNotMatch(help, /这些是当前内置/);
});

test("content script loads and handles paste without module runtime errors", () => {
  const listeners = new Map();
  const appended = [];
  class HTMLElement {}
  class HTMLTextAreaElement extends HTMLElement {
    constructor() {
      super();
      this.value = "";
    }

    dispatchEvent(event) {
      this.lastEvent = event;
    }
  }
  class HTMLInputElement extends HTMLTextAreaElement {}
  class InputEvent {
    constructor(type, options) {
      this.type = type;
      this.options = options;
    }
  }

  const document = {
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    getElementById() {
      return null;
    },
    createElement() {
      return {
        id: "",
        style: { cssText: "" },
        children: [],
        append(...children) {
          this.children.push(...children);
        },
        addEventListener() {},
        setAttribute(name, value) {
          this[name] = value;
        },
        remove() {},
        set textContent(value) {
          this.text = value;
        },
        innerHTML: "",
        querySelector() {
          return { addEventListener() {} };
        },
      };
    },
    documentElement: {
      append(element) {
        appended.push(element);
      },
    },
  };

  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/content.js"), "utf8");
  vm.runInNewContext(script, {
    document,
    HTMLElement,
    HTMLTextAreaElement,
    HTMLInputElement,
    InputEvent,
    navigator: { clipboard: { writeText() {} } },
    Map,
    Set,
  });

  assert.equal(typeof listeners.get("paste"), "function");
  listeners.get("paste")({
    preventDefault() {},
    clipboardData: {
      getData() {
        return "Authorization: Bearer sk-live-abc1234567890";
      },
    },
    target: new HTMLTextAreaElement(),
  });
  assert.equal(appended.length, 1);
});

test("content script does not depend on innerHTML for the paste panel", () => {
  const listeners = new Map();
  const appended = [];
  class HTMLElement {}
  class HTMLTextAreaElement extends HTMLElement {
    constructor() {
      super();
      this.value = "";
    }

    dispatchEvent(event) {
      this.lastEvent = event;
    }
  }
  class HTMLInputElement extends HTMLTextAreaElement {}
  class InputEvent {
    constructor(type, options) {
      this.type = type;
      this.options = options;
    }
  }

  function createElement() {
    return {
      id: "",
      style: { cssText: "" },
      children: [],
      dataset: {},
      append(...children) {
        this.children.push(...children);
      },
      addEventListener() {},
      setAttribute(name, value) {
        this[name] = value;
      },
      remove() {},
      set textContent(value) {
        this.text = value;
      },
      set innerHTML(_value) {
        throw new TypeError("TrustedHTML assignment required");
      },
    };
  }

  const document = {
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    getElementById() {
      return null;
    },
    createElement,
    documentElement: {
      append(element) {
        appended.push(element);
      },
    },
  };

  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/content.js"), "utf8");
  vm.runInNewContext(script, {
    document,
    HTMLElement,
    HTMLTextAreaElement,
    HTMLInputElement,
    InputEvent,
    navigator: { clipboard: { writeText() {} } },
    console,
    Map,
    Set,
  });

  listeners.get("paste")({
    preventDefault() {},
    clipboardData: {
      getData() {
        return "Authorization: Bearer sk-live-abc1234567890";
      },
    },
    target: new HTMLTextAreaElement(),
  });
  assert.equal(appended.length, 1);
});

test("content script blocks secret paste until the user chooses an action", () => {
  const listeners = new Map();
  const appended = [];
  class HTMLElement {}
  class HTMLTextAreaElement extends HTMLElement {
    constructor() {
      super();
      this.value = "";
    }

    dispatchEvent(event) {
      this.lastEvent = event;
    }
  }
  class HTMLInputElement extends HTMLTextAreaElement {}
  class InputEvent {
    constructor(type, options) {
      this.type = type;
      this.options = options;
    }
  }

  function createElement(tagName) {
    return {
      tagName,
      id: "",
      type: "",
      style: { cssText: "" },
      children: [],
      listeners: new Map(),
      append(...children) {
        this.children.push(...children);
      },
      addEventListener(type, listener) {
        this.listeners.set(type, listener);
      },
      setAttribute(name, value) {
        this[name] = value;
      },
      remove() {
        this.removed = true;
      },
      dispatch(type) {
        this.listeners.get(type)?.();
      },
      set textContent(value) {
        this.text = value;
      },
    };
  }

  const document = {
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    getElementById() {
      return null;
    },
    createElement,
    documentElement: {
      append(element) {
        appended.push(element);
      },
    },
  };

  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/content.js"), "utf8");
  vm.runInNewContext(script, {
    document,
    HTMLElement,
    HTMLTextAreaElement,
    HTMLInputElement,
    InputEvent,
    navigator: { clipboard: { writeText() {} } },
    Map,
    Set,
  });

  let defaultPrevented = false;
  const target = new HTMLTextAreaElement();
  listeners.get("paste")({
    preventDefault() {
      defaultPrevented = true;
    },
    clipboardData: {
      getData() {
        return "Authorization: Bearer sk-live-abc1234567890";
      },
    },
    target,
  });

  assert.equal(defaultPrevented, true);
  assert.equal(target.value, "");

  const redactButton = appended[0].children[2].children[0].children[1];
  redactButton.dispatch("click");

  assert.equal(target.value, "Authorization: Bearer [BEARER_TOKEN_1]");
});

test("content script explains the risk and only offers one-time choices on first prompt", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", { language: "zh-Hant-TW" });
  const target = new harness.HTMLTextAreaElement();

  harness.paste(
    "curl 'https://api.example.test/users?api_key=secret_query_value' \\\n+  -H 'Authorization: Bearer sk-live-abc1234567890'\nSENTRY_DSN=https://public:private@sentry.example.test/42",
    target,
  );

  const panel = harness.appended[0];
  const labels = getActionButtonLabels(panel);
  const text = collectText(panel);

  assert.equal(panel.className, "veil-prompt");
  assert.deepEqual(labels, ["不脱敏，继续粘贴", "本次脱敏"]);
  assert.match(text, /发现可能泄漏的信息，已暂停粘贴/);
  assert.match(text, /你可以先脱敏，再继续粘贴/);
  assert.match(text, /严重/);
  assert.match(text, /提醒/);
  assert.match(text, /URL 参数 api_key/);
  assert.match(text, /会泄漏请求里的密钥或访问口令/);
  assert.match(text, /Bearer 访问令牌/);
  assert.match(text, /会泄漏账号或服务访问权限/);
  assert.match(text, /Sentry DSN/);
  assert.match(text, /可能暴露项目上报入口/);
});

test("content script uses English UI when browser language is not zh-prefixed", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", { language: "en-US" });
  const target = new harness.HTMLTextAreaElement();

  harness.paste(
    "curl 'https://api.example.test/users?api_key=secret_query_value' \\\n+  -H 'Authorization: Bearer sk-live-abc1234567890'\nSENTRY_DSN=https://public:private@sentry.example.test/42",
    target,
  );

  const panel = harness.appended[0];
  const labels = getActionButtonLabels(panel);
  const text = collectText(panel);

  assert.deepEqual(labels, ["Paste without redaction", "Redact once"]);
  assert.equal(panel.className, "veil-prompt");
  assert.match(text, /Possible leak found\. Paste paused/);
  assert.match(text, /You can redact first, then continue pasting/);
  assert.match(text, /Critical/);
  assert.match(text, /Notice/);
  assert.match(text, /URL parameter api_key/);
  assert.match(text, /May leak keys or access tokens from the request/);
  assert.match(text, /Bearer access token/);
  assert.match(text, /May leak account or service access/);
  assert.match(text, /Sentry DSN/);
  assert.match(text, /May expose a project event ingestion endpoint/);
});

test("content script opens extension options through the background service worker", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  harness.paste("Authorization: Bearer sk-live-abc1234567890", new harness.HTMLTextAreaElement());

  const settingsButton = getButtons(harness.appended[0]).find(
    (button) => button.textContent === "设置",
  );
  assert.ok(settingsButton, "settings button should exist");

  settingsButton.dispatch("click");

  assert.equal(harness.optionsOpenCount, 0);
  assert.equal(harness.sentMessages.length, 1);
  assert.equal(harness.sentMessages[0].type, "VEILPASTE_OPEN_OPTIONS");
  assert.deepEqual(harness.openedUrls, []);
});

test("content script opens English settings through the background service worker", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", { language: "en-US" });
  harness.paste("Authorization: Bearer sk-live-abc1234567890", new harness.HTMLTextAreaElement());

  const settingsButton = getButtons(harness.appended[0]).find(
    (button) => button.textContent === "Settings",
  );
  assert.ok(settingsButton, "settings button should exist");

  settingsButton.dispatch("click");

  assert.equal(harness.optionsOpenCount, 0);
  assert.equal(harness.sentMessages.length, 1);
  assert.equal(harness.sentMessages[0].type, "VEILPASTE_OPEN_OPTIONS");
  assert.deepEqual(harness.openedUrls, []);
});

test("content script falls back to background message when direct options API is unavailable", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", {
    openOptionsPageAvailable: false,
  });
  harness.paste("Authorization: Bearer sk-live-abc1234567890", new harness.HTMLTextAreaElement());

  const settingsButton = getButtons(harness.appended[0]).find(
    (button) => button.textContent === "设置",
  );
  assert.ok(settingsButton, "settings button should exist");

  settingsButton.dispatch("click");

  assert.equal(harness.optionsOpenCount, 0);
  assert.equal(harness.sentMessages.length, 1);
  assert.equal(harness.sentMessages[0].type, "VEILPASTE_OPEN_OPTIONS");
});

test("background script opens options page and replies to content script", () => {
  const listeners = new Map();
  let optionsOpenCount = 0;
  let response = null;
  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/background.js"), "utf8");

  vm.runInNewContext(script, {
    chrome: {
      runtime: {
        onMessage: {
          addListener(listener) {
            listeners.set("message", listener);
          },
        },
        openOptionsPage(callback) {
          optionsOpenCount += 1;
          callback?.();
        },
      },
    },
  });

  const keepAlive = listeners.get("message")(
    { type: "VEILPASTE_OPEN_OPTIONS" },
    {},
    (payload) => {
      response = payload;
    },
  );

  assert.equal(keepAlive, true);
  assert.equal(optionsOpenCount, 1);
  assert.equal(response.ok, true);
});

test("help page exposes a local auto-redact setting", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");
  const optionsScript = fs.readFileSync(
    path.join(root, "chrome-extension/dist/options.js"),
    "utf8",
  );

  assert.match(help, /autoRedactEnabled/);
  assert.match(help, /VeilPaste 设置/);
  assert.match(optionsScript, /chrome\.storage\.local/);
  assert.match(help, /不再弹出确认/);
  assert.match(help, /class="switch"/);
});

test("options page renders sidebar settings sections", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /VeilPaste 设置/);
  assert.match(help, /class="app-shell"/);
  assert.match(help, /class="side"/);
  assert.match(help, /class="main-card"/);
  assert.doesNotMatch(help, /class="app-top"/);
  assert.doesNotMatch(help, /class="frame"/);
  assert.doesNotMatch(help, />控制台</);
  assert.match(help, /data-section="overview"/);
  assert.match(help, /data-section="sites"/);
  assert.match(help, /data-section="rules"/);
  assert.match(help, /data-section="redaction"/);
  assert.match(help, /data-section="privacy"/);
  assert.match(help, /data-section="tester"/);
  assert.match(help, /保护网址/);
  assert.match(help, /保护规则/);
  assert.match(help, /测试区/);
});

test("options page explains protected sites and deferred custom URLs", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /https:\/\/chatgpt\.com\/\*/);
  assert.match(help, /https:\/\/claude\.ai\/\*/);
  assert.match(help, /https:\/\/www\.perplexity\.ai\/\*/);
  assert.match(help, /只在这些 AI 网站检查粘贴内容/);
  assert.match(help, /自定义网址/);
  assert.match(help, /当前不能自己添加网址/);
});

test("options page displays built-in rules by severity", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /严重/);
  assert.match(help, /提醒/);
  assert.match(help, /OpenAI Key/);
  assert.match(help, /Bearer 访问令牌/);
  assert.match(help, /Cookie sessionid/);
  assert.match(help, /URL 参数 token\/api_key/);
  assert.match(help, /Sentry DSN/);
  assert.match(help, /Webhook URL/);
  assert.match(help, /内置启用/);
});

test("options page avoids platform and subscription promises", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.doesNotMatch(help, /订阅/);
  assert.doesNotMatch(help, /团队内部 AI/);
  assert.doesNotMatch(help, /未来可配置/);
  assert.doesNotMatch(help, /安全产品|安全工具/);
  assert.match(help, /本地处理/);
  assert.match(help, /本地检查粘贴内容/);
  assert.match(help, /不上传内容/);
  assert.match(help, /脱敏规则/);
  assert.match(help, /原则/);
  assert.doesNotMatch(help, /高置信规则/);
  assert.doesNotMatch(help, /默认边界/);
  assert.doesNotMatch(help, /host permissions|content script|风险记忆|storage/);
});

test("options page defaults to redaction settings", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /class="[^"]*page-section[^"]*is-active[^"]*"[^>]*data-section="redaction"/);
  assert.match(help, /启用“以后自动脱敏”/);
  assert.match(help, /不再弹出确认/);
});

test("content prompt keeps design close control without auto-redact enabled", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input = "Authorization: Bearer sk-live-abc1234567890";

  harness.paste(input, new harness.HTMLTextAreaElement());

  const panel = harness.appended[0];
  const closeButton = getButtons(panel).find((button) => button.className === "close");

  assert.ok(closeButton, "prompt should include the design close control");
  assert.deepEqual(getActionButtonLabels(panel), ["不脱敏，继续粘贴", "本次脱敏"]);
});

test("options page states privacy and storage boundaries", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /不上传粘贴内容/);
  assert.match(help, /不保存敏感值/);
  assert.match(help, /不保存完整 prompt/);
  assert.match(help, /不发网络请求/);
  assert.match(help, /只记住你是否开启“以后自动脱敏”/);
  assert.match(help, /设置页只在你点击设置时打开/);
  assert.match(help, /只在 ChatGPT、Claude、Perplexity、豆包和 Qwen 上工作/);
});

test("chrome docs explain extension permissions precisely", () => {
  const readme = fs.readFileSync(path.join(root, "chrome-extension/README.md"), "utf8");
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(readme, /storage/);
  assert.match(readme, /只保存.*autoRedactEnabled|只保存用户设置/);
  assert.match(readme, /background.*打开.*设置|background service worker.*options|background service worker only opens the extension options page/i);
  assert.match(help, /只记住你是否开启“以后自动脱敏”/);
  assert.match(help, /设置页只在你点击设置时打开/);
  for (const text of [readme, help]) {
    assert.match(text, /ChatGPT/);
    assert.match(text, /Claude/);
    assert.match(text, /Perplexity/);
    assert.match(text, /不上传/);
    assert.match(text, /不保存敏感值/);
  }
});

test("options page includes a local rule tester", () => {
  const help = fs.readFileSync(path.join(root, "chrome-extension/help.html"), "utf8");

  assert.match(help, /id="ruleTesterInput"/);
  assert.match(help, /id="ruleTesterRun"/);
  assert.match(help, /id="ruleTesterFindings"/);
  assert.match(help, /id="ruleTesterOutput"/);
  assert.match(help, /本地测试/);
});

test("options script wires local tester without network or storage writes", () => {
  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/options.js"), "utf8");

  assert.match(script, /ruleTesterInput/);
  assert.match(script, /ruleTesterRun/);
  assert.match(script, /detectAndRedact/);
  assert.doesNotMatch(script, /fetch\(/);
  assert.doesNotMatch(script, /XMLHttpRequest/);
  assert.doesNotMatch(script, /chrome\.storage\.local\.set\([^)]*ruleTester/);
});

test("options script supports sidebar section switching", () => {
  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/options.js"), "utf8");

  assert.match(script, /querySelectorAll\("\.nav-item"\)/);
  assert.match(script, /querySelectorAll\("\.page-section"\)/);
  assert.match(script, /data-target/);
  assert.match(script, /hidden/);
  assert.match(script, /is-active/);
});

test("content script sorts critical risks before warnings", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const target = new harness.HTMLTextAreaElement();

  harness.paste(
    "SENTRY_DSN=https://public:private@sentry.example.test/42\nAuthorization: Bearer sk-live-abc1234567890",
    target,
  );

  const text = collectText(harness.appended[0]);
  assert.ok(
    text.indexOf("Bearer 访问令牌") < text.indexOf("Sentry DSN"),
    `critical risk should appear before warning; got ${text}`,
  );
});

test("content script treats plain paste as first-use again", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input = "Authorization: Bearer sk-live-abc1234567890";

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[0].dispatch("click");

  harness.paste(input, new harness.HTMLTextAreaElement());

  assert.deepEqual(getActionButtonLabels(harness.appended[1]), ["不脱敏，继续粘贴", "本次脱敏"]);
});

test("content script does not offer always-redact in the confirmation panel", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input = "Authorization: Bearer sk-live-abc1234567890";

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[1].dispatch("click");

  harness.paste(input, new harness.HTMLTextAreaElement());
  assert.deepEqual(getActionButtonLabels(latestPanel(harness)), ["不脱敏，继续粘贴", "本次脱敏"]);
});

test("content script auto-redacts immediately when auto-redact is enabled", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", { autoRedactEnabled: true });
  const input = "Authorization: Bearer sk-live-abc1234567890";
  const target = new harness.HTMLTextAreaElement();

  harness.paste(input, target);

  assert.equal(target.value, "Authorization: Bearer [BEARER_TOKEN_1]");
  assert.equal(panelCount(harness), 0);
  assert.equal(harness.appended.length, 1);
  assert.equal(harness.appended[0].id, "veilpaste-toast");
  assert.match(collectText(harness.appended[0]), /VeilPaste 已自动脱敏/);
});

test("content script waits for auto-redact setting before showing a prompt", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", {
    autoRedactEnabled: true,
    delayStorageGet: true,
  });
  const input = "Authorization: Bearer sk-live-abc1234567890";
  const target = new harness.HTMLTextAreaElement();

  harness.paste(input, target);

  assert.equal(target.value, "");
  assert.equal(panelCount(harness), 0);

  harness.flushStorageGet();

  assert.equal(target.value, "Authorization: Bearer [BEARER_TOKEN_1]");
  assert.equal(panelCount(harness), 0);
  assert.equal(harness.appended.filter((element) => element.id === "veilpaste-toast").length, 1);
});

test("content script shows solved-risk toast after one-time redaction", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input =
    "curl 'https://api.example.test/users?api_key=secret_query_value' \\\n+  -H 'Authorization: Bearer sk-live-abc1234567890'";

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[1].dispatch("click");

  assert.equal(harness.appended.length, 2);
  const toast = harness.appended[1];
  const text = collectText(toast);
  assert.equal(toast.className, "veil-toast");
  assert.match(text, /VeilPaste 已完成脱敏/);
  assert.match(text, /已处理/);
  assert.match(text, /Bearer 访问令牌/);
  assert.match(text, /URL 参数 api_key/);
  assert.match(text, /已粘贴脱敏后的文本/);
  assert.equal(harness.timeouts.length, 1);
  assert.equal(harness.timeouts[0].delay, 4000);
});

test("content script uses English solved-risk toast when browser language is not zh-prefixed", () => {
  const harness = createContentScriptHarness("https://chatgpt.com", { language: "en-US" });
  const input =
    "curl 'https://api.example.test/users?api_key=secret_query_value' \\\n+  -H 'Authorization: Bearer sk-live-abc1234567890'";

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[1].dispatch("click");

  const text = collectText(harness.appended[1]);
  assert.match(text, /VeilPaste redacted the paste/);
  assert.match(text, /Handled:/);
  assert.match(text, /Bearer access token/);
  assert.match(text, /URL parameter api_key/);
  assert.match(text, /Redacted text was pasted/);
});

test("content script summarizes many solved risks in the redaction toast", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input = [
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
    "Authorization: Bearer sk-live-abc1234567890",
    "Cookie: sessionid=prod_cookie_value; auth_token=prod_auth_value",
    "SENTRY_DSN=https://public:private@sentry.example.test/42",
  ].join("\n");

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[1].dispatch("click");

  const text = collectText(harness.appended[1]);
  assert.match(text, /另有/);
});

test("content script does not show solved-risk toast for plain paste", () => {
  const harness = createContentScriptHarness("https://chatgpt.com");
  const input = "Authorization: Bearer sk-live-abc1234567890";

  harness.paste(input, new harness.HTMLTextAreaElement());
  getActionButtons(harness.appended[0])[0].dispatch("click");

  assert.equal(harness.appended.length, 1);
  assert.equal(harness.timeouts.length, 0);
});

test("content script auto-redact setting applies without prompt on each protected origin", () => {
  const input = "Authorization: Bearer sk-live-abc1234567890";
  const chatgpt = createContentScriptHarness("https://chatgpt.com", { autoRedactEnabled: true });
  const claude = createContentScriptHarness("https://claude.ai", { autoRedactEnabled: true });

  const chatgptTarget = new chatgpt.HTMLTextAreaElement();
  chatgpt.paste(input, chatgptTarget);
  assert.equal(chatgptTarget.value, "Authorization: Bearer [BEARER_TOKEN_1]");
  assert.equal(panelCount(chatgpt), 0);

  const claudeTarget = new claude.HTMLTextAreaElement();
  claude.paste(input, claudeTarget);
  assert.equal(claudeTarget.value, "Authorization: Bearer [BEARER_TOKEN_1]");
  assert.equal(panelCount(claude), 0);
});

function createContentScriptHarness(origin, options = {}) {
  const listeners = new Map();
  const appended = [];
  const openedUrls = [];
  const sentMessages = [];
  const timeouts = [];
  const pendingStorageGets = [];
  let optionsOpenCount = 0;

  class HTMLElement {}
  class HTMLTextAreaElement extends HTMLElement {
    constructor() {
      super();
      this.value = "";
    }

    dispatchEvent(event) {
      this.lastEvent = event;
    }
  }
  class HTMLInputElement extends HTMLTextAreaElement {}
  class InputEvent {
    constructor(type, options) {
      this.type = type;
      this.options = options;
    }
  }

  function createElement(tagName) {
    return {
      tagName,
      id: "",
      type: "",
      style: { cssText: "" },
      children: [],
      listeners: new Map(),
      append(...children) {
        this.children.push(...children);
      },
      addEventListener(type, listener) {
        this.listeners.set(type, listener);
      },
      setAttribute(name, value) {
        this[name] = value;
      },
      remove() {
        this.removed = true;
      },
      dispatch(type) {
        this.listeners.get(type)?.();
      },
      set textContent(value) {
        this.text = value;
      },
      get textContent() {
        return this.text ?? "";
      },
    };
  }

  const document = {
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    getElementById() {
      return null;
    },
    createElement,
    documentElement: {
      append(element) {
        appended.push(element);
      },
    },
  };

  const script = fs.readFileSync(path.join(root, "chrome-extension/dist/content.js"), "utf8");
  vm.runInNewContext(script, {
    chrome: {
      runtime: {
        getURL(pathName) {
          return `chrome-extension://veilpaste/${pathName}`;
        },
        sendMessage(message) {
          sentMessages.push(message);
        },
        ...(options.openOptionsPageAvailable === false
          ? {}
          : {
              openOptionsPage(callback) {
                optionsOpenCount += 1;
                callback?.();
              },
            }),
      },
      storage: {
        local: {
          get(defaults, callback) {
            const settings = {
              ...defaults,
              autoRedactEnabled: options.autoRedactEnabled ?? defaults.autoRedactEnabled,
            };
            if (options.delayStorageGet) {
              pendingStorageGets.push(() => callback(settings));
              return;
            }
            callback(settings);
          },
          onChanged: {
            addListener() {},
          },
        },
      },
    },
    document,
    HTMLElement,
    HTMLTextAreaElement,
    HTMLInputElement,
    InputEvent,
    location: { origin },
    navigator: {
      clipboard: { writeText() {} },
      language: options.language ?? "zh-CN",
      languages: [options.language ?? "zh-CN"],
    },
    window: {
      open(url, target, features) {
        openedUrls.push({ url, target, features });
      },
    },
    console,
    setTimeout(callback, delay) {
      timeouts.push({ callback, delay });
      return timeouts.length;
    },
    clearTimeout() {},
    Map,
    Set,
  });

  const harness = {
    appended,
    get optionsOpenCount() {
      return optionsOpenCount;
    },
    sentMessages,
    openedUrls,
    timeouts,
    HTMLTextAreaElement,
    lastTarget: null,
    paste(text, target) {
      harness.lastTarget = target;
      listeners.get("paste")({
        preventDefault() {},
        clipboardData: {
          getData() {
            return text;
          },
        },
        target,
      });
    },
    flushStorageGet() {
      for (const flush of pendingStorageGets.splice(0)) {
        flush();
      }
    },
  };

  return harness;
}

function collectText(element) {
  return [element.text ?? "", ...element.children.flatMap((child) => [collectText(child)])].join(
    " ",
  );
}

function getButtons(element) {
  const matches = element.tagName === "button" ? [element] : [];
  return matches.concat(...element.children.map(getButtons));
}

function getButtonLabels(element) {
  return getButtons(element).map((button) => button.textContent);
}

function getActionButtons(element) {
  return getButtons(element).filter(
    (button) => !["×", "i", "设置", "Settings"].includes(button.textContent),
  );
}

function getActionButtonLabels(element) {
  return getActionButtons(element).map((button) => button.textContent);
}

function latestPanel(harness) {
  return harness.appended.filter((element) => element.id === "veilpaste-panel").at(-1);
}

function panelCount(harness) {
  return harness.appended.filter((element) => element.id === "veilpaste-panel").length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
