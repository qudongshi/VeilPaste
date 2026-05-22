# VeilPaste

VeilPaste 是一个小而美的本地开发者工具，用来在把日志、curl、`.env`、HTTP headers 或配置片段粘贴给 AI 之前，先发现明显的密钥、会话和访问令牌，并协助脱敏，从而降低 AI 粘贴场景下的安全风险。

它不是安全产品，也不保证脱敏后的内容一定可以安全发送给外部 AI 服务。试用时请只使用 fake secret 或已经脱敏的样例，不要提交真实密钥。

## 试用方式

CLI：

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste
```

Chrome 插件：

- 在 Chrome 扩展页加载 `chrome-extension/`。
- 打开 ChatGPT、Claude、Perplexity、豆包或 Qwen。
- 粘贴包含 fake secret 的文本。
- 如果浏览器语言以 `zh` 开头，插件弹框显示中文；其他语言默认显示英文。

## 当前边界

- 只处理明显的开发者密钥、访问令牌、会话、连接串和部分配置凭证。
- Chrome 版本只拦截 paste，不拦截 submit/send/click。
- 默认本地处理，不上传粘贴内容，不保存敏感值。
- 如果需要了解漏检范围，请看 `docs/known-misses.md`。
