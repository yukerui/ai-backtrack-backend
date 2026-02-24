# ai-backtrack-backend

用于 `ai-backtrack` 的后端代理服务，提供以下能力：

- OpenAI 兼容接口：`/v1/chat/completions`
- 输入策略预检接口：`/v1/policy/check`
- Artifact 文件鉴权下载：`/artifacts?token=...`
- 健康检查：`/healthz`

服务实现文件：`codex-openai-proxy.mjs`。

## 1. 运行要求

- Node.js 18+
- pnpm 9+
- 可用的 Codex CLI（`codex`）
- 可选：`cloudflared`（如果要走 Cloudflare Tunnel）

## 2. 本地启动

```bash
pnpm install
cp .env.example .env.local
# 编辑 .env.local
pnpm dev
```

默认监听：`http://127.0.0.1:15722`

健康检查：

```bash
curl http://127.0.0.1:15722/healthz
```

## 3. 必配环境变量

最小可用配置：

- `CLAUDE_CODE_GATEWAY_TOKEN`：API Bearer Token（前端调用必须一致）
- `CODEX_CLI_BIN`：`codex` 可执行文件路径（例如 `/usr/local/bin/codex`）
- `CODEX_MODEL`：默认模型（例如 `gpt-5-codex`）

前后端联动建议必配：

- `INTERNAL_TASK_KEY`：前端调用后端预检/任务时的内部鉴权键（需与前端一致）

Artifact 下载必配：

- `ARTIFACTS_SIGNING_SECRET`：用于签名校验 `/artifacts` token

## 4. 基金问题分类器（模型判定）

开启后，`/v1/policy/check` 与 `/v1/chat/completions` 会优先做模型判定，而不是只靠正则。

关键变量：

- `FUND_CLASSIFIER_ENABLED=true`
- `FUND_CLASSIFIER_API_BASE`
- `FUND_CLASSIFIER_MODEL`
- `FUND_CLASSIFIER_SECRET`
- `FUND_CLASSIFIER_SECRET_HEADER`（默认 `authorization`）
- `FUND_CLASSIFIER_SECRET_PREFIX`（默认 `Bearer`）
- `FUND_CLASSIFIER_TIMEOUT_MS`（默认 `5000`）
- `FUND_CLASSIFIER_FAIL_OPEN`（默认 `false`）
- `FUND_CLASSIFIER_PROMPT`（可选，自定义）

示例：

```env
FUND_CLASSIFIER_ENABLED=true
FUND_CLASSIFIER_API_BASE=http://74.176.208.79:8317
FUND_CLASSIFIER_MODEL=gemini-3.1-pro-high
FUND_CLASSIFIER_SECRET=replace-me
FUND_CLASSIFIER_SECRET_HEADER=authorization
FUND_CLASSIFIER_SECRET_PREFIX=Bearer
FUND_CLASSIFIER_TIMEOUT_MS=5000
FUND_CLASSIFIER_FAIL_OPEN=false
```

## 5. API 示例

所有接口都需要 Bearer Token：

```http
Authorization: Bearer <CLAUDE_CODE_GATEWAY_TOKEN>
```

### 5.1 预检接口

```bash
curl -sS http://127.0.0.1:15722/v1/policy/check \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer YOUR_TOKEN' \
  -d '{"text":"QQQ在春节期间的涨幅是多少"}'
```

### 5.2 Chat Completions（stream）

```bash
curl -N http://127.0.0.1:15722/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer YOUR_TOKEN' \
  -d '{
    "model":"gpt-5-codex",
    "stream":true,
    "messages":[{"role":"user","content":"对比159501和513100过去两年的收益"}]
  }'
```

### 5.3 Artifact 下载

```bash
curl -L 'http://127.0.0.1:15722/artifacts?token=<signed-token>' -o report.html
```

## 6. Debian 部署（systemd）

以下示例假设代码部署在 `/opt/ai-backtrack-backend`。

### 6.1 安装依赖

```bash
sudo apt update
sudo apt install -y curl git
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
sudo corepack enable
sudo corepack prepare pnpm@latest --activate
```

### 6.2 拉取代码并安装

```bash
sudo mkdir -p /opt/ai-backtrack-backend
sudo chown -R $USER:$USER /opt/ai-backtrack-backend
git clone https://github.com/yukerui/ai-backtrack-backend.git /opt/ai-backtrack-backend
cd /opt/ai-backtrack-backend
pnpm install --frozen-lockfile
cp .env.example .env.local
# 编辑 .env.local
```

### 6.3 配置 systemd

创建 `/etc/systemd/system/ai-backtrack-backend.service`：

```ini
[Unit]
Description=ai-backtrack backend proxy
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/ai-backtrack-backend
Environment=NODE_ENV=production
ExecStart=/usr/bin/env pnpm start
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-backtrack-backend
sudo systemctl status ai-backtrack-backend
```

查看日志：

```bash
journalctl -u ai-backtrack-backend -f
```

## 7. Cloudflare Tunnel（可选）

快速隧道：

```bash
pnpm tunnel
```

命名隧道：

```bash
pnpm tunnel:named -- ai-chatbot-backend
```

示例配置见：`cloudflared/config.example.yml`。

## 8. 常见问题

- `401 Unauthorized`
  - Bearer Token 不匹配，检查 `CLAUDE_CODE_GATEWAY_TOKEN`。
- `blocked_non_fund`
  - 被策略拦截，检查分类器配置或 `ENFORCE_FUND_ONLY`。
- `Artifact file not found`
  - token 对应路径不存在，或 `ARTIFACTS_SIGNING_SECRET` 不一致。
- `Turnstile verification failed`
  - 前端未带 token 或后端 Turnstile 配置错误。

## 9. 安全建议

- 不要把 `.env.local`、密钥、token 提交到仓库。
- 生产环境建议配合 WAF / IP 限流。
- 建议开启 HTTPS 终端（Nginx/Caddy/Cloudflare）。
