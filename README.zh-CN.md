# VeilPaste

粘贴给 AI 前，先把明显敏感信息遮住。

VeilPaste 会在本地检查你准备粘贴的日志、curl、`.env`、HTTP header 和配置片段。发现 API Key、访问令牌、Cookie、私钥或数据库连接串时，它会把这些值替换成清晰的占位符。

它不会上传你的粘贴内容，不保存敏感值，也不需要账号。

## 快速试用

```bash
echo 'Authorization: Bearer sk-live-abc1234567890' | veilpaste
```

输出：

```txt
Authorization: Bearer [BEARER_TOKEN_1]
```

macOS 剪贴板用法：

```bash
pbpaste | veilpaste --quiet | pbcopy
```

预览将被脱敏的内容：

```bash
veilpaste scrub fixtures/curl/request.curl --preview
```

## Chrome 插件

Chrome 插件会在 ChatGPT、Claude、Perplexity、豆包和 Qwen 中检查粘贴内容。

发现可能泄漏的信息时，它会先暂停粘贴，并让你选择：

- 不脱敏，继续粘贴
- 本次脱敏
- 以后自动脱敏

本地测试时，在 Chrome 扩展页加载 `chrome-extension/` 目录即可。

## 可恢复脱敏

如果你希望 AI 修改配置文件后还能恢复原值，可以在本地保存映射文件：

```bash
veilpaste scrub .env --map .veilpaste/session.json > redacted.env
```

示例：

```txt
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
```

会变成：

```txt
OPENAI_API_KEY=[OPENAI_KEY_1]
```

AI 返回修改后的文件后，可以在本地恢复：

```bash
veilpaste restore ai-output.env --map .veilpaste/session.json
```

映射文件包含原始敏感值。只保存在本地，不要提交到仓库。

## 当前能识别什么

VeilPaste 优先处理高置信的开发者敏感信息：

- Bearer Token 和 Basic Auth
- API Key header
- JWT 和 Cookie
- OpenAI、AWS、GitHub、Stripe Key
- `.env` 中的 secret 值
- 数据库和服务连接串
- Slack、Discord webhook
- URL 中的用户名密码
- PEM 私钥
- npm、pypirc、Docker registry 凭证
- URL 参数里的 `token`、`api_key`、`secret`、`password`

默认不处理普通邮箱、手机号、IP、姓名、项目名或 UUID。

## 使用边界

- 默认本地处理。
- 默认不上传内容。
- 默认不收集遥测。
- 不需要账号。
- 脱敏能降低风险，但不能证明一段内容一定适合发给 AI。

漏检范围见 [docs/known-misses.md](docs/known-misses.md)。
