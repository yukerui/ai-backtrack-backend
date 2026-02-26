#!/usr/bin/env node
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { config as loadDotenv } from "dotenv";

function getRepoRoot() {
  const cwd = process.cwd();
  const candidate = path.resolve(cwd, "..");
  if (fs.existsSync(path.resolve(cwd, "backend")) && fs.existsSync(path.resolve(cwd, "front"))) {
    return cwd;
  }
  if (
    fs.existsSync(path.resolve(candidate, "backend")) &&
    fs.existsSync(path.resolve(candidate, "front"))
  ) {
    return candidate;
  }
  return cwd;
}

const REPO_ROOT = getRepoRoot();
const backendRoot = process.cwd();
for (const envFile of [".env.local", ".env"]) {
  const envPath = path.join(backendRoot, envFile);
  if (fs.existsSync(envPath)) {
    loadDotenv({ path: envPath, override: false });
  }
}

const HOST = process.env.CLAUDE_PROXY_HOST || "127.0.0.1";
const PORT = Number.parseInt(process.env.CLAUDE_PROXY_PORT || "15722", 10);
const TOKEN = process.env.CLAUDE_CODE_GATEWAY_TOKEN || "";
const BLOCK_URL_INPUT = (process.env.BLOCK_URL_INPUT || "true").toLowerCase() !== "false";
const URL_BLOCKED_REPLY =
  process.env.URL_BLOCKED_REPLY ||
  "Sorry, I cannot access or download links due to security policy. Please paste text directly.";
const REDACT_SENSITIVE_OUTPUT =
  (process.env.REDACT_SENSITIVE_OUTPUT || "true").toLowerCase() !== "false";
const ENFORCE_FUND_BACKTEST_ONLY =
  (process.env.ENFORCE_FUND_BACKTEST_ONLY || "false").toLowerCase() !== "false";
const ENFORCE_FUND_ONLY =
  (process.env.ENFORCE_FUND_ONLY || "true").toLowerCase() !== "false";
const FUND_CLASSIFIER_ENABLED =
  (process.env.FUND_CLASSIFIER_ENABLED || "true").toLowerCase() !== "false";
const FUND_CLASSIFIER_API_BASE = (process.env.FUND_CLASSIFIER_API_BASE || "").trim();
const FUND_CLASSIFIER_MODEL = (process.env.FUND_CLASSIFIER_MODEL || "").trim();
const FUND_CLASSIFIER_SECRET =
  process.env.FUND_CLASSIFIER_SECRET || process.env.FUND_CLASSIFIER_API_KEY || "";
const FUND_CLASSIFIER_SECRET_HEADER = (process.env.FUND_CLASSIFIER_SECRET_HEADER || "authorization")
  .toLowerCase()
  .trim();
const FUND_CLASSIFIER_SECRET_PREFIX =
  process.env.FUND_CLASSIFIER_SECRET_PREFIX === undefined
    ? "Bearer"
    : String(process.env.FUND_CLASSIFIER_SECRET_PREFIX).trim();
const FUND_CLASSIFIER_TIMEOUT_MS = Number.parseInt(
  process.env.FUND_CLASSIFIER_TIMEOUT_MS || "5000",
  10
);
const FUND_CLASSIFIER_FAIL_OPEN =
  (process.env.FUND_CLASSIFIER_FAIL_OPEN || "false").toLowerCase() !== "false";
const BLOCK_TRADING_ADVICE_INPUT =
  (process.env.BLOCK_TRADING_ADVICE_INPUT || "false").toLowerCase() !== "false";
const BLOCK_POLITICAL_INPUT =
  (process.env.BLOCK_POLITICAL_INPUT || "true").toLowerCase() !== "false";
const BLOCK_ADULT_INPUT =
  (process.env.BLOCK_ADULT_INPUT || "true").toLowerCase() !== "false";
const FORCE_CHINESE_OUTPUT =
  (process.env.FORCE_CHINESE_OUTPUT || "true").toLowerCase() !== "false";
const FORCE_HTML_BACKTEST_CHART =
  (process.env.FORCE_HTML_BACKTEST_CHART || "true").toLowerCase() !== "false";
const TURNSTILE_ENABLED =
  (process.env.TURNSTILE_ENABLED || "false").toLowerCase() !== "false";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const TURNSTILE_VERIFY_URL =
  process.env.TURNSTILE_VERIFY_URL ||
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TURNSTILE_TOKEN_HEADER = (process.env.TURNSTILE_TOKEN_HEADER || "x-turnstile-token")
  .toLowerCase()
  .trim();
const TURNSTILE_REQUIRED_ACTION = (process.env.TURNSTILE_REQUIRED_ACTION || "").trim();
const TURNSTILE_REQUIRED_HOSTNAME = (process.env.TURNSTILE_REQUIRED_HOSTNAME || "").trim();
const INTERNAL_TASK_KEY = process.env.INTERNAL_TASK_KEY || "";
const RATE_LIMIT_ENABLED =
  (process.env.RATE_LIMIT_ENABLED || "true").toLowerCase() !== "false";
const RATE_LIMIT_WINDOW_MS = Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000", 10);
const RATE_LIMIT_MAX_REQUESTS = Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "30", 10);
const CACHE_ENABLED = (process.env.CACHE_ENABLED || "true").toLowerCase() !== "false";
const CACHE_TTL_MS = Number.parseInt(process.env.CACHE_TTL_MS || "120000", 10);
const CACHE_MAX_ITEMS = Number.parseInt(process.env.CACHE_MAX_ITEMS || "500", 10);
const PROXY_DEBUG_VERBOSE =
  (process.env.PROXY_DEBUG_VERBOSE || "false").toLowerCase() !== "false";

const ARTIFACTS_SIGNING_SECRET =
  process.env.ARTIFACTS_SIGNING_SECRET || process.env.AUTH_SECRET || "";
const ARTIFACT_ROOTS = [
  path.resolve(REPO_ROOT, "backend/artifacts"),
  path.resolve(REPO_ROOT, "front/artifacts"),
  path.resolve(REPO_ROOT, "artifacts"),
];

const TRADING_ADVICE_BLOCKED_REPLY =
  process.env.TRADING_ADVICE_BLOCKED_REPLY ||
  "抱歉，我不提供买卖建议或择时建议。";
const POLITICAL_BLOCKED_REPLY =
  process.env.POLITICAL_BLOCKED_REPLY ||
  "抱歉，该话题不在可服务范围内。";
const ADULT_BLOCKED_REPLY =
  process.env.ADULT_BLOCKED_REPLY ||
  "抱歉，该话题不在可服务范围内。";
const NON_BACKTEST_BLOCKED_REPLY =
  process.env.NON_BACKTEST_BLOCKED_REPLY ||
  "该请求当前未通过策略校验，请调整后重试。";
const NON_FUND_BLOCKED_REPLY =
  process.env.NON_FUND_BLOCKED_REPLY ||
  "当前仅支持基金相关问题。你也可以询问“你能做什么”。";
const FUND_CLASSIFIER_PROMPT = (
  process.env.FUND_CLASSIFIER_PROMPT ||
  [
    "你是基金领域的输入分类器，只做放行/拦截判断。",
    "任务：判断用户问题是否属于基金或 ETF 相关，输出 allow 或 deny。",
    "判定为 allow 的场景：",
    "1) 场内/场外基金、ETF、QDII、指数基金、溢价、回测、定投、轮动、净值、申赎、基金代码等问题。",
    "2) 代码或标的虽是美股 ETF（如 QQQ、SPY、TQQQ），但问题本质在基金/ETF表现或对比。",
    "3) 询问助手能力范围（例如：你能做什么、有哪些功能）。",
    "判定为 deny 的场景：",
    "1) 与基金/ETF无关的话题（闲聊、编程、政治、成人、泛新闻等）。",
    "输出要求：仅输出 JSON 对象，不要 markdown，不要额外文字。",
    "JSON 格式：{\"label\":\"allow\"|\"deny\",\"reason\":\"不超过20字中文\"}",
  ].join("\n")
).trim();

const CODEX_BIN = process.env.CODEX_CLI_BIN || process.env.CLAUDE_CLI_BIN || "codex";
const CODEX_MODEL = process.env.CODEX_MODEL || process.env.CLAUDE_CODE_MODEL || "gpt-5-codex";
const CODEX_CONFIG_FILE = (process.env.CODEX_CONFIG_FILE || "config/config.toml").trim();
const CODEX_CONFIG_PATH = path.isAbsolute(CODEX_CONFIG_FILE)
  ? CODEX_CONFIG_FILE
  : path.resolve(backendRoot, CODEX_CONFIG_FILE);
const CODEX_CONFIG_HOME = path.dirname(CODEX_CONFIG_PATH);
const CODEX_SKIP_APPROVALS =
  (process.env.CODEX_DANGEROUSLY_BYPASS_APPROVALS_AND_SANDBOX || "true").toLowerCase() === "true";
const CODEX_DISABLE_RESUME =
  (process.env.CODEX_DISABLE_RESUME || "true").toLowerCase() !== "false";
const CODEX_EPHEMERAL =
  (process.env.CODEX_EPHEMERAL || "true").toLowerCase() !== "false";
const CODEX_REASONING_EFFORT = (
  process.env.CODEX_REASONING_EFFORT ||
  process.env.CODEX_MODEL_REASONING_EFFORT ||
  "high"
)
  .toLowerCase()
  .trim();
const CODEX_RUST_LOG = (
  process.env.CODEX_RUST_LOG || "error,codex_core::rollout::list=off"
).trim();

const URL_REGEX = /((https?:\/\/|www\.)\S+)/i;
const TRADING_ADVICE_REGEX =
  /(能不能买|能买吗|可以买|什么时候买|什么时候卖|买入|卖出|建仓|加仓|减仓|抄底|止盈|止损|仓位建议|投资建议|推荐.*买|target price|entry point|exit point|buy now|sell now)/i;
const POLITICAL_REGEX =
  /(政治|涉政|国家领导人|政府内幕|选举操控|政变|分裂国家|颠覆政权|敏感政治|propaganda|regime change|terroris(?:m|t))/i;
const ADULT_REGEX =
  /(色情|涉黄|黄网|黄片|约炮|嫖娼|成人视频|成人网站|成人内容|裸聊|性交易|porn|xxx|nude|sex chat|escort)/i;
const FUND_KEYWORD_REGEX =
  /(基金|etf|qdii|场内|场外|纳指|nasdaq|中概|指数基金|标的|代码|ticker|净值|\b\d{6}\b)/i;
const BACKTEST_KEYWORD_REGEX =
  /(回测|定投|轮动|区间收益|收益对比|历史收益|年化|最大回撤|波动率|夏普|胜率|净值曲线|再平衡|策略表现|backtest|dca|momentum|drawdown|cagr|sharpe)/i;
const CAPABILITY_QUERY_REGEX =
  /(你能做什么|你有哪些功能|你会什么|怎么用|功能清单|能力清单|可用功能|help|capabilities)/i;
const GUEST_SENSITIVE_COMMAND_REGEX =
  /(^|[;&|]\s*)(git\s+push|rm(\s+-[A-Za-z-]+)*\s+\S+|git\s+reset\s+--hard|git\s+checkout\s+--|sudo\s+|chmod\s+|chown\s+)(\s|$)/i;

const SESSION_QUEUES = new Map();
const CHAT_TO_CODEX_THREAD = new Map();
const RATE_LIMIT_BUCKETS = new Map();
const RESPONSE_CACHE = new Map();

function json(res, status, payload) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function debugLog(tag, message, payload) {
  if (!PROXY_DEBUG_VERBOSE) {
    return;
  }
  const suffix =
    payload === undefined ? "" : ` ${JSON.stringify(payload, null, 0).slice(0, 2000)}`;
  process.stdout.write(`[debug] ${tag} ${message}${suffix}\n`);
}

function toBase64Url(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buffer
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64Url(input) {
  const base64 = String(input).replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  return Buffer.from(base64 + pad, "base64");
}

function verifyArtifactToken(token) {
  if (!ARTIFACTS_SIGNING_SECRET) {
    return { ok: false, error: "Missing artifact signing secret" };
  }
  const [payloadB64, sigB64] = String(token || "").split(".");
  if (!payloadB64 || !sigB64) {
    return { ok: false, error: "Invalid token" };
  }
  const payload = fromBase64Url(payloadB64);
  const expectedSig = createHmac("sha256", ARTIFACTS_SIGNING_SECRET).update(payload).digest();
  const providedSig = fromBase64Url(sigB64);
  if (expectedSig.length !== providedSig.length) {
    return { ok: false, error: "Invalid token" };
  }
  if (!timingSafeEqual(expectedSig, providedSig)) {
    return { ok: false, error: "Invalid token" };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(payload.toString("utf8"));
  } catch {
    return { ok: false, error: "Invalid token" };
  }
  if (!parsed?.p || typeof parsed.e !== "number") {
    return { ok: false, error: "Invalid token" };
  }
  if (Date.now() > parsed.e) {
    return { ok: false, error: "Token expired" };
  }
  return { ok: true, path: parsed.p };
}

function getContentType(targetPath) {
  if (targetPath.endsWith(".html")) {
    return "text/html; charset=utf-8";
  }
  if (targetPath.endsWith(".csv")) {
    return "text/csv; charset=utf-8";
  }
  if (targetPath.endsWith(".json")) {
    return "application/json; charset=utf-8";
  }
  return "text/plain; charset=utf-8";
}

function parseBearerToken(headers) {
  const auth = headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return "";
  }
  return auth.slice("Bearer ".length).trim();
}

function normalizeUserType(raw) {
  return String(raw || "").trim().toLowerCase() === "guest" ? "guest" : "regular";
}

function isGuestUserType(userType) {
  return normalizeUserType(userType) === "guest";
}

function hasUrl(text) {
  return URL_REGEX.test(text || "");
}

function normalizeClientIp(req) {
  const direct = (req.socket?.remoteAddress || "").trim();
  const cf = String(req.headers["cf-connecting-ip"] || "").trim();
  const xff = String(req.headers["x-forwarded-for"] || "")
    .split(",")[0]
    .trim();
  return cf || xff || direct || "unknown";
}

function checkRateLimit(ip) {
  if (!RATE_LIMIT_ENABLED) {
    return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS };
  }
  const now = Date.now();
  const windowMs = Number.isFinite(RATE_LIMIT_WINDOW_MS) && RATE_LIMIT_WINDOW_MS > 0
    ? RATE_LIMIT_WINDOW_MS
    : 60000;
  const maxRequests = Number.isFinite(RATE_LIMIT_MAX_REQUESTS) && RATE_LIMIT_MAX_REQUESTS > 0
    ? RATE_LIMIT_MAX_REQUESTS
    : 30;
  const bucket = RATE_LIMIT_BUCKETS.get(ip);
  if (!bucket || now >= bucket.resetAt) {
    const next = { count: 1, resetAt: now + windowMs };
    RATE_LIMIT_BUCKETS.set(ip, next);
    return { allowed: true, remaining: maxRequests - 1, resetAt: next.resetAt };
  }
  bucket.count += 1;
  if (bucket.count > maxRequests) {
    return { allowed: false, remaining: 0, resetAt: bucket.resetAt };
  }
  return { allowed: true, remaining: maxRequests - bucket.count, resetAt: bucket.resetAt };
}

function getRequestTurnstileToken(req, body) {
  const headerToken = String(req.headers[TURNSTILE_TOKEN_HEADER] || "").trim();
  if (headerToken) {
    return headerToken;
  }
  const bodyToken = typeof body?.turnstileToken === "string" ? body.turnstileToken.trim() : "";
  return bodyToken;
}

async function verifyTurnstile({ token, ip }) {
  if (!TURNSTILE_ENABLED) {
    return { ok: true, reason: "disabled" };
  }
  if (!TURNSTILE_SECRET) {
    return { ok: false, reason: "missing_secret" };
  }
  if (!token) {
    return { ok: false, reason: "missing_token" };
  }

  const payload = new URLSearchParams();
  payload.set("secret", TURNSTILE_SECRET);
  payload.set("response", token);
  if (ip && ip !== "unknown") {
    payload.set("remoteip", ip);
  }

  try {
    const resp = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: payload.toString(),
    });
    if (!resp.ok) {
      return { ok: false, reason: "verify_http_error" };
    }
    const data = await resp.json();
    if (!data?.success) {
      const codes = Array.isArray(data?.["error-codes"]) ? data["error-codes"].join(",") : "";
      return { ok: false, reason: `verify_failed:${codes || "unknown"}` };
    }
    if (TURNSTILE_REQUIRED_ACTION && data.action !== TURNSTILE_REQUIRED_ACTION) {
      return { ok: false, reason: "action_mismatch" };
    }
    if (TURNSTILE_REQUIRED_HOSTNAME && data.hostname !== TURNSTILE_REQUIRED_HOSTNAME) {
      return { ok: false, reason: "hostname_mismatch" };
    }
    return { ok: true, reason: "ok" };
  } catch {
    return { ok: false, reason: "verify_exception" };
  }
}

function cacheKey({ model, prompt }) {
  const hash = createHash("sha256");
  hash.update(model || "");
  hash.update("\n");
  hash.update(prompt || "");
  return hash.digest("hex");
}

function readCache(key) {
  if (!CACHE_ENABLED) {
    return "";
  }
  const now = Date.now();
  const hit = RESPONSE_CACHE.get(key);
  if (!hit) {
    return "";
  }
  if (hit.expiresAt <= now) {
    RESPONSE_CACHE.delete(key);
    return "";
  }
  return hit.content || "";
}

function writeCache(key, content) {
  if (!CACHE_ENABLED || !content) {
    return;
  }
  const ttl = Number.isFinite(CACHE_TTL_MS) && CACHE_TTL_MS > 0 ? CACHE_TTL_MS : 120000;
  RESPONSE_CACHE.set(key, {
    content,
    expiresAt: Date.now() + ttl,
  });
  if (RESPONSE_CACHE.size > Math.max(CACHE_MAX_ITEMS, 1)) {
    const oldest = RESPONSE_CACHE.keys().next();
    if (!oldest.done) {
      RESPONSE_CACHE.delete(oldest.value);
    }
  }
}

function previewText(text, max = 80) {
  const oneLine = String(text || "").replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max)}...` : oneLine;
}

function parseJsonObjectFromText(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    return null;
  }

  const stripped = raw
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  const candidates = [stripped];
  const firstBrace = stripped.indexOf("{");
  const lastBrace = stripped.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const sliced = stripped.slice(firstBrace, lastBrace + 1).trim();
    if (sliced && sliced !== stripped) {
      candidates.push(sliced);
    }
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // try next candidate
    }
  }

  return null;
}

function normalizeFundClassifierLabel(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  const lower = text.toLowerCase();

  if (
    lower === "deny" ||
    lower.includes("deny") ||
    lower.includes("reject") ||
    lower.includes("block") ||
    lower.includes("non_fund") ||
    lower.includes("not_fund") ||
    lower.includes("not fund") ||
    /拒绝|拦截|非基金|不相关|无关/.test(text)
  ) {
    return "deny";
  }

  if (
    lower === "allow" ||
    lower.includes("allow") ||
    lower.includes("pass") ||
    lower.includes("fund_related") ||
    /允许|放行|基金|etf|qdii|能力咨询/.test(text)
  ) {
    return "allow";
  }

  return "";
}

function resolveFundClassifierEndpoint(baseUrl) {
  const trimmed = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!trimmed) {
    return "";
  }
  if (trimmed.endsWith("/chat/completions")) {
    return trimmed;
  }
  if (trimmed.endsWith("/v1")) {
    return `${trimmed}/chat/completions`;
  }
  return `${trimmed}/v1/chat/completions`;
}

function createFundClassifierHeaders() {
  const headers = { "content-type": "application/json" };
  if (!FUND_CLASSIFIER_SECRET || !FUND_CLASSIFIER_SECRET_HEADER) {
    return headers;
  }
  const prefix = FUND_CLASSIFIER_SECRET_PREFIX
    ? `${FUND_CLASSIFIER_SECRET_PREFIX}${FUND_CLASSIFIER_SECRET_PREFIX.endsWith(" ") ? "" : " "}`
    : "";
  headers[FUND_CLASSIFIER_SECRET_HEADER] = `${prefix}${FUND_CLASSIFIER_SECRET}`;
  return headers;
}

async function classifyFundIntentByModel(input) {
  if (!FUND_CLASSIFIER_ENABLED) {
    return { available: false, source: "disabled" };
  }

  const endpoint = resolveFundClassifierEndpoint(FUND_CLASSIFIER_API_BASE);
  if (!endpoint || !FUND_CLASSIFIER_MODEL || !FUND_CLASSIFIER_SECRET) {
    return { available: false, source: "missing_config" };
  }

  const timeoutMs = Number.isFinite(FUND_CLASSIFIER_TIMEOUT_MS) && FUND_CLASSIFIER_TIMEOUT_MS > 0
    ? FUND_CLASSIFIER_TIMEOUT_MS
    : 5000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: createFundClassifierHeaders(),
      body: JSON.stringify({
        model: FUND_CLASSIFIER_MODEL,
        temperature: 0,
        max_tokens: 120,
        stream: false,
        messages: [
          { role: "system", content: FUND_CLASSIFIER_PROMPT },
          { role: "user", content: input },
        ],
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      return { available: false, source: `http_${response.status}` };
    }
    const data = await response.json();
    const content = extractTextFromMessageContent(data?.choices?.[0]?.message?.content);
    const parsed = parseJsonObjectFromText(content);
    const label = normalizeFundClassifierLabel(
      parsed?.label || parsed?.decision || parsed?.result || content
    );
    if (!label) {
      return { available: false, source: "invalid_output" };
    }
    const reason = typeof parsed?.reason === "string" ? parsed.reason.trim() : "";
    return {
      available: true,
      isFund: label === "allow",
      reason: reason || (label === "allow" ? "fund_related" : "non_fund"),
      source: "model",
    };
  } catch (error) {
    const name = error && typeof error === "object" ? error.name : "";
    if (name === "AbortError") {
      return { available: false, source: "timeout" };
    }
    return { available: false, source: "exception" };
  } finally {
    clearTimeout(timer);
  }
}

async function classifyInputPolicy(text) {
  const input = String(text || "").trim();
  if (!input) {
    return { allowed: false, reason: "empty", reply: "请先输入问题。" };
  }

  if (BLOCK_POLITICAL_INPUT && POLITICAL_REGEX.test(input)) {
    return { allowed: false, reason: "political", reply: POLITICAL_BLOCKED_REPLY };
  }

  if (BLOCK_ADULT_INPUT && ADULT_REGEX.test(input)) {
    return { allowed: false, reason: "adult", reply: ADULT_BLOCKED_REPLY };
  }

  if (BLOCK_TRADING_ADVICE_INPUT && TRADING_ADVICE_REGEX.test(input)) {
    return { allowed: false, reason: "trading_advice", reply: TRADING_ADVICE_BLOCKED_REPLY };
  }

  if (ENFORCE_FUND_ONLY) {
    const isCapabilityQuery = CAPABILITY_QUERY_REGEX.test(input);
    if (!isCapabilityQuery) {
      const modelDecision = await classifyFundIntentByModel(input);
      if (modelDecision.available && !modelDecision.isFund) {
        return {
          allowed: false,
          reason: "non_fund",
          reply: NON_FUND_BLOCKED_REPLY,
          source: modelDecision.source,
        };
      }
      if (!modelDecision.available) {
        process.stdout.write(
          `[policy] fund_classifier_unavailable source=${modelDecision.source} fail_open=${FUND_CLASSIFIER_FAIL_OPEN}\n`
        );
        if (!FUND_CLASSIFIER_FAIL_OPEN) {
          const isFundQuery = FUND_KEYWORD_REGEX.test(input);
          if (!isFundQuery) {
            return {
              allowed: false,
              reason: "non_fund",
              reply: NON_FUND_BLOCKED_REPLY,
              source: "regex",
            };
          }
        }
      }
    }
  }

  if (ENFORCE_FUND_BACKTEST_ONLY) {
    const isFundBacktest = FUND_KEYWORD_REGEX.test(input) && BACKTEST_KEYWORD_REGEX.test(input);
    if (!isFundBacktest) {
      return { allowed: false, reason: "non_backtest", reply: NON_BACKTEST_BLOCKED_REPLY };
    }
  }

  return { allowed: true, reason: "ok", reply: "" };
}

function respondWithFixedReply({ res, stream, model, reply }) {
  if (stream) {
    writeOpenAiSseStart(res);
    const id = `chatcmpl-${randomUUID()}`;
    writeOpenAiSseChunk(res, createChunk({ id, model, content: reply }));
    writeOpenAiSseChunk(res, createDoneChunk({ id, model }));
    writeOpenAiSseDone(res);
    return;
  }

  json(res, 200, {
    id: `chatcmpl-${randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: reply,
        },
        finish_reason: "stop",
      },
    ],
  });
}

function redactSensitive(text) {
  if (!REDACT_SENSITIVE_OUTPUT || !text) {
    return text;
  }

  const patterns = [
    /(bearer\s+)[A-Za-z0-9._~+/=-]+/gi,
    /((api[_-]?key|token|secret|password)\s*[:=]\s*)([^\s"'`]+)/gi,
    /(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)/g,
    /\b(sk|rk|pk)_[A-Za-z0-9]{10,}\b/g,
  ];

  let output = text;
  output = output.replace(patterns[0], "$1[REDACTED]");
  output = output.replace(patterns[1], "$1[REDACTED]");
  output = output.replace(patterns[2], "$1\n[REDACTED]\n$2");
  output = output.replace(patterns[3], "[REDACTED]");
  return output;
}

function extractTextFromMessageContent(content) {
  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") {
          return part;
        }
        if (part && typeof part === "object") {
          if (typeof part.text === "string") {
            return part.text;
          }
          if (typeof part.input_text === "string") {
            return part.input_text;
          }
          if (typeof part.content === "string") {
            return part.content;
          }
        }
        return "";
      })
      .join("\n");
  }

  if (content && typeof content === "object") {
    if (typeof content.text === "string") {
      return content.text;
    }
  }

  return "";
}

function getLastUserText(messages) {
  if (!Array.isArray(messages)) {
    return "";
  }

  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const msg = messages[i];
    if (msg?.role === "user") {
      return extractTextFromMessageContent(msg.content).trim();
    }
  }

  return "";
}

function buildForcedPrompt(userText, userType = "regular") {
  const rules = [];

  if (FORCE_CHINESE_OUTPUT) {
    rules.push("你必须仅使用中文输出（包含最终回答与 thinking/reasoning），禁止英文正文。");
  }

  if (FORCE_HTML_BACKTEST_CHART) {
    rules.push(
      [
        "你必须生成一个可下载的 HTML 交互图表文件，路径使用 artifacts/*.html。",
        "HTML 必须包含 <html>、<head>、<body>，并包含 <div id=\"backtestChart\"></div> 与内联 <script> 绘图。",
        "如果用户未提供完整回测数据，也要生成可运行示例曲线，并在页面中标注“示例数据，仅用于展示”。",
        "最终文字回复中必须包含该 HTML 文件的下载/打开链接（例如 artifacts/xxx.html）。",
      ].join("")
    );
  }

  if (isGuestUserType(userType)) {
    rules.push(
      "你当前处于访客安全模式：严禁执行敏感命令（例如 git push、rm、git reset --hard、git checkout --、sudo、chmod、chown），仅允许只读命令。"
    );
  }


  if (rules.length === 0) {
    return userText;
  }

  return `请严格遵守以下输出规则：\n${rules.map((x, i) => `${i + 1}. ${x}`).join("\n")}\n\n用户请求：\n${userText}`;
}

function summarizeItemEvent(item) {
  if (!item || typeof item !== "object") {
    return "";
  }

  const itemType = typeof item.type === "string" ? item.type : "event";
  const itemTypeLabelMap = {
    reasoning: "思考",
    command_execution: "命令执行",
    file_change: "文件变更",
    tool_call: "工具调用",
    agent_message: "助手消息",
    event: "事件",
  };
  const typeLabel = itemTypeLabelMap[itemType] || itemType;
  const details = [];

  for (const key of ["tool_name", "name", "command", "cmd", "description", "text"]) {
    if (typeof item[key] === "string" && item[key].trim()) {
      details.push(item[key].trim());
      break;
    }
  }

  if (details.length === 0 && typeof item.arguments === "string" && item.arguments.trim()) {
    details.push(item.arguments.trim());
  }

  if (details.length === 0 && item.arguments && typeof item.arguments === "object") {
    try {
      details.push(JSON.stringify(item.arguments));
    } catch {
      // ignore serialization error
    }
  }

  if (details.length > 0) {
    return `【${typeLabel}】 ${sanitizeReasoningText(details.join(" "))}`;
  }
  return `【${typeLabel}】`;
}

function sanitizeReasoningText(text) {
  if (!text) {
    return "";
  }

  return text
    .replace(
      /(?:\/Users\/|\/home\/|\/private\/var\/folders\/)[^\s"'`]+/g,
      "[path]"
    )
    .replace(/[A-Za-z]:\\[^\\s"'`]+/g, "[path]");
}

function prettifyReasoningText(text) {
  if (!text) {
    return "";
  }

  const labelMap = {
    command_execution: "命令执行",
    file_change: "文件变更",
    error: "错误",
  };

  const normalized = sanitizeReasoningText(text)
    .replace(/\r\n/g, "\n")
    .replace(/\*{3,}/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (!normalized) {
    return "";
  }

  const lines = normalized
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) =>
      line.replace(/\[(command_execution|file_change|error)\]/gi, (_, key) => `【${labelMap[key.toLowerCase()] || key}】`)
    );

  return lines.join("\n");
}

function formatCommandExecution(item, { userType = "regular" } = {}) {
  const command = [
    item.command,
    item.cmd,
    item.description,
    item.text,
    typeof item.arguments === "string" ? item.arguments : "",
  ].find((candidate) => typeof candidate === "string" && candidate.trim());

  if (command) {
    const trimmed = command.trim();
    if (/(\bpython\b.*-m\s+pip\s+install|\bpip3?\s+install)\b/i.test(trimmed)) {
      return "";
    }
    const cleaned = sanitizeReasoningText(trimmed);
    if (isGuestUserType(userType) && GUEST_SENSITIVE_COMMAND_REGEX.test(trimmed)) {
      return `【访客模式拦截】\n已拒绝敏感命令：${cleaned}`;
    }
    return `【命令执行】\n${cleaned}`;
  }

  return "【命令执行】";
}

function extractCodexEventParts(obj, { userType = "regular" } = {}) {
  const parts = {
    textDelta: "",
    reasoningDelta: "",
  };

  if (!obj || typeof obj !== "object") {
    return parts;
  }

  if (obj.type === "error" && typeof obj.message === "string") {
    parts.reasoningDelta = `【错误】 ${sanitizeReasoningText(obj.message)}`;
    return parts;
  }

  // Keep reasoning cleaner: only consume completed events to avoid noisy duplicates.
  if (obj.type === "item.completed") {
    const item = obj.item;
    if (item?.type === "agent_message" && typeof item.text === "string") {
      parts.textDelta = item.text;
      return parts;
    }

    if (item?.type === "reasoning" && typeof item.text === "string") {
      parts.reasoningDelta = prettifyReasoningText(item.text);
      return parts;
    }

    if (item?.type === "command_execution") {
      const formatted = formatCommandExecution(item, { userType });
      if (formatted) {
        parts.reasoningDelta = formatted;
      }
      return parts;
    }

    parts.reasoningDelta = prettifyReasoningText(summarizeItemEvent(item));
    return parts;
  }

  return parts;
}

function getCodexConfigArgs() {
  const args = [];
  if (CODEX_REASONING_EFFORT) {
    args.push("-c", `model_reasoning_effort="${CODEX_REASONING_EFFORT}"`);
  }
  return args;
}

function stripRolloutNoise(stderrText) {
  return String(stderrText || "")
    .split("\n")
    .filter(
      (line) =>
        !/codex_core::rollout::list: state db missing rollout path for thread/i.test(line.trim())
    )
    .join("\n")
    .trim();
}

function parseStructuredCodexError(raw) {
  const text = String(raw || "").trim();
  if (!text) {
    return "";
  }
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed?.error?.message === "string" && parsed.error.message.trim()) {
      return parsed.error.message.trim();
    }
  } catch {
    // ignore parse failures and fallback to raw text
  }
  return text;
}

function runCodex({
  prompt,
  chatId,
  isNewSession,
  onTextChunk,
  onReasoningChunk,
  traceTag = "",
  userType = "regular",
}) {
  return new Promise((resolve, reject) => {
    const normalizedUserType = normalizeUserType(userType);
    const guestMode = isGuestUserType(normalizedUserType);
    const codexConfigArgs = getCodexConfigArgs();
    let args = ["exec", "--json", "--skip-git-repo-check"];

    if (guestMode) {
      args.push("--sandbox", "read-only");
    }

    if (CODEX_SKIP_APPROVALS && !guestMode) {
      args.push("--dangerously-bypass-approvals-and-sandbox");
    }

    if (CODEX_MODEL) {
      args.push("--model", CODEX_MODEL);
    }

    if (CODEX_EPHEMERAL) {
      args.push("--ephemeral");
    }
    args.push(...codexConfigArgs);

    const knownThreadId = CHAT_TO_CODEX_THREAD.get(chatId);
    if (!CODEX_DISABLE_RESUME && !isNewSession && knownThreadId) {
      args = [
        "exec",
        "resume",
        "--json",
        "--skip-git-repo-check",
        ...(guestMode ? ["--sandbox", "read-only"] : []),
        ...(CODEX_EPHEMERAL ? ["--ephemeral"] : []),
        ...codexConfigArgs,
        ...(CODEX_SKIP_APPROVALS && !guestMode
          ? ["--dangerously-bypass-approvals-and-sandbox"]
          : []),
        ...(CODEX_MODEL ? ["--model", CODEX_MODEL] : []),
        knownThreadId,
        prompt,
      ];
    } else {
      args.push(prompt);
    }

    const childEnv = { ...process.env };
    if (CODEX_RUST_LOG && !childEnv.RUST_LOG) {
      childEnv.RUST_LOG = CODEX_RUST_LOG;
    }
    if (CODEX_CONFIG_PATH && fs.existsSync(CODEX_CONFIG_PATH)) {
      childEnv.CODEX_HOME = CODEX_CONFIG_HOME;
    }
    const venvBin = path.resolve(REPO_ROOT, ".venv", "bin");
    if (fs.existsSync(venvBin)) {
      childEnv.VIRTUAL_ENV = path.resolve(REPO_ROOT, ".venv");
      childEnv.PATH = `${venvBin}${path.delimiter}${childEnv.PATH || ""}`;
    }

    const child = spawn(CODEX_BIN, args, {
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });

    debugLog(traceTag, "spawn_codex", {
      chatId,
      userType: normalizedUserType,
      guestMode,
      isNewSession,
      knownThreadId: knownThreadId || "",
      args,
      configPath: CODEX_CONFIG_PATH,
      promptLength: String(prompt || "").length,
    });

    let stdoutBuffer = "";
    let stderrText = "";
    let fullText = "";
    let threadId = knownThreadId;
    let codexError = "";
    let eventCount = 0;
    let textDeltaCount = 0;
    let reasoningDeltaCount = 0;

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      stdoutBuffer += text;

      const lines = stdoutBuffer.split("\n");
      stdoutBuffer = lines.pop() || "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) {
          continue;
        }

        try {
          const obj = JSON.parse(trimmed);
          eventCount += 1;
          if (obj.type === "thread.started" && typeof obj.thread_id === "string") {
            threadId = obj.thread_id;
            debugLog(traceTag, "thread_started", { threadId });
          }
          if (obj.type === "error" && typeof obj.message === "string") {
            codexError = parseStructuredCodexError(obj.message);
            debugLog(traceTag, "codex_error_event", { message: codexError });
          }
          if (obj.type === "turn.failed" && typeof obj?.error?.message === "string") {
            codexError = parseStructuredCodexError(obj.error.message);
            debugLog(traceTag, "codex_turn_failed", { message: codexError });
          }

          const { textDelta, reasoningDelta } = extractCodexEventParts(obj, {
            userType: normalizedUserType,
          });
          if (reasoningDelta) {
            reasoningDeltaCount += 1;
            onReasoningChunk?.(reasoningDelta);
          }

          if (textDelta) {
            textDeltaCount += 1;
            if (fullText) {
              fullText += "\n";
            }
            fullText += textDelta;
            onTextChunk?.(textDelta);
          }

          if (obj?.run_id || String(obj?.id || "").startsWith("run_")) {
            debugLog(traceTag, "run_event", {
              type: obj.type || "",
              id: obj.id || "",
              run_id: obj.run_id || "",
            });
          }
        } catch {
          // ignore non-JSON logs from Codex CLI
        }
      }
    });

    child.stderr.on("data", (chunk) => {
      stderrText += chunk.toString("utf8");
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (code) => {
      if (stdoutBuffer.trim()) {
        try {
          const obj = JSON.parse(stdoutBuffer.trim());
          if (obj.type === "thread.started" && typeof obj.thread_id === "string") {
            threadId = obj.thread_id;
          }
          if (obj.type === "error" && typeof obj.message === "string") {
            codexError = parseStructuredCodexError(obj.message);
          }
          if (obj.type === "turn.failed" && typeof obj?.error?.message === "string") {
            codexError = parseStructuredCodexError(obj.error.message);
          }
          const { textDelta, reasoningDelta } = extractCodexEventParts(obj, {
            userType: normalizedUserType,
          });
          if (reasoningDelta) {
            onReasoningChunk?.(reasoningDelta);
          }
          if (textDelta) {
            if (fullText) {
              fullText += "\n";
            }
            fullText += textDelta;
          }
        } catch {
          // ignore tail log noise
        }
      }

      if (code !== 0) {
        const cleanedStderr = stripRolloutNoise(stderrText);
        const message = codexError || cleanedStderr || `codex exited with code ${code}`;
        debugLog(traceTag, "codex_close_error", {
          code,
          message,
          eventCount,
          textDeltaCount,
          reasoningDeltaCount,
        });
        reject(new Error(message));
        return;
      }

      debugLog(traceTag, "codex_close_ok", {
        code,
        threadId: threadId || "",
        eventCount,
        textDeltaCount,
        reasoningDeltaCount,
        textLength: fullText.trim().length,
      });
      resolve({ text: fullText.trim(), stderr: stderrText, threadId });
    });
  });
}

function enqueueBySession(sessionId, task) {
  const previous = SESSION_QUEUES.get(sessionId) || Promise.resolve();

  const next = previous
    .catch(() => undefined)
    .then(task)
    .finally(() => {
      if (SESSION_QUEUES.get(sessionId) === next) {
        SESSION_QUEUES.delete(sessionId);
      }
    });

  SESSION_QUEUES.set(sessionId, next);
  return next;
}

function runCodexWithFallback({
  prompt,
  chatId,
  isNewSession,
  onTextChunk,
  onReasoningChunk,
  traceTag = "",
  userType = "regular",
}) {
  return enqueueBySession(chatId, async () => {
    try {
      const result = await runCodex({
        prompt,
        chatId,
        isNewSession,
        onTextChunk,
        onReasoningChunk,
        traceTag,
        userType,
      });
      if (result.threadId) {
        CHAT_TO_CODEX_THREAD.set(chatId, result.threadId);
      }
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (
        !isNewSession &&
        /not found|unknown session|invalid session|missing rollout path|state db missing rollout path/i.test(
          message
        )
      ) {
        CHAT_TO_CODEX_THREAD.delete(chatId);
        const retried = await runCodex({
          prompt,
          chatId,
          isNewSession: true,
          onTextChunk,
          onReasoningChunk,
          traceTag,
          userType,
        });
        if (retried.threadId) {
          CHAT_TO_CODEX_THREAD.set(chatId, retried.threadId);
        }
        return retried;
      }
      throw error;
    }
  });
}

function writeOpenAiSseStart(res) {
  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    connection: "keep-alive",
    "cache-control": "no-cache, no-transform",
  });
}

function writeOpenAiSseChunk(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function writeOpenAiSseDone(res) {
  res.write("data: [DONE]\n\n");
  res.end();
}

function createChunk({ id, model, content, reasoning }) {
  return {
    id,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        delta: {
          ...(content ? { content } : {}),
          ...(reasoning ? { reasoning } : {}),
        },
        finish_reason: null,
      },
    ],
  };
}

function createDoneChunk({ id, model }) {
  return {
    id,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        delta: {},
        finish_reason: "stop",
      },
    ],
  };
}

const server = http.createServer(async (req, res) => {
  const reqId = randomUUID().slice(0, 8);
  const startedAt = Date.now();
  let decision = "pending";
  let clientIp = "-";
  let inputPreview = "";

  res.on("finish", () => {
    const ms = Date.now() - startedAt;
    const preview = inputPreview ? ` q="${inputPreview}"` : "";
    process.stdout.write(
      `[access] id=${reqId} ip=${clientIp} ${req.method || "-"} ${req.url || "-"} status=${res.statusCode} ms=${ms} decision=${decision}${preview}\n`
    );
  });

  try {
    const url = new URL(req.url || "/", `http://${HOST}:${PORT}`);
    const traceTag = `req=${reqId}`;

    if (req.method === "GET" && url.pathname === "/healthz") {
      decision = "healthz";
      return json(res, 200, { ok: true });
    }

    if (req.method === "GET" && url.pathname === "/artifacts") {
      const token = url.searchParams.get("token");
      const verified = verifyArtifactToken(token);
      if (!verified.ok) {
        decision = "artifact_invalid_token";
        return json(res, 403, { error: verified.error });
      }
      const normalizedPath = String(verified.path).replace(/^\/+/, "");
      const candidatePaths = [path.resolve(REPO_ROOT, normalizedPath)];
      if (normalizedPath.startsWith("artifacts/")) {
        candidatePaths.push(path.resolve(REPO_ROOT, `backend/${normalizedPath}`));
        candidatePaths.push(path.resolve(REPO_ROOT, `front/${normalizedPath}`));
      }

      const allowedCandidates = candidatePaths.filter((candidatePath) =>
        ARTIFACT_ROOTS.some((root) => candidatePath.startsWith(root + path.sep))
      );
      if (allowedCandidates.length === 0) {
        decision = "artifact_invalid_path";
        return json(res, 400, { error: "Path traversal is not allowed" });
      }

      for (const candidatePath of allowedCandidates) {
        try {
          const content = fs.readFileSync(candidatePath);
          decision = "artifact_ok";
          res.writeHead(200, {
            "content-type": getContentType(candidatePath),
            "cache-control": "no-store",
          });
          res.end(content);
          return;
        } catch {
          // try next candidate
        }
      }

      decision = "artifact_not_found";
      return json(res, 404, { error: "Artifact file not found" });
    }

    const isChatCompletions = req.method === "POST" && url.pathname === "/v1/chat/completions";
    const isPolicyCheck = req.method === "POST" && url.pathname === "/v1/policy/check";
    if (!isChatCompletions && !isPolicyCheck) {
      decision = "not_found";
      return json(res, 404, { error: { message: "Not found" } });
    }

    const bearer = parseBearerToken(req.headers);
    if (!bearer || (TOKEN && bearer !== TOKEN)) {
      decision = "unauthorized";
      return json(res, 401, { error: { message: "Unauthorized" } });
    }

    clientIp = normalizeClientIp(req);
    const rate = checkRateLimit(clientIp);
    if (!rate.allowed) {
      const retryAfterSec = Math.max(1, Math.ceil(((rate.resetAt || Date.now()) - Date.now()) / 1000));
      res.setHeader("retry-after", String(retryAfterSec));
      decision = "rate_limited";
      return json(res, 429, { error: { message: "Too Many Requests" } });
    }

    let rawBody = "";
    for await (const chunk of req) {
      rawBody += chunk.toString("utf8");
    }

    let body;
    try {
      body = JSON.parse(rawBody);
      debugLog(traceTag, "request_body_parsed", {
        path: url.pathname,
        method: req.method,
        bodyKeys: Object.keys(body || {}),
        rawBodyLength: rawBody.length,
      });
    } catch {
      decision = "invalid_json";
      return json(res, 400, { error: { message: "Invalid JSON body" } });
    }

    const model = body.model || CODEX_MODEL;
    const stream = Boolean(body.stream);
    const userType = normalizeUserType(req.headers["x-user-type"]);
    const explicitText =
      typeof body?.text === "string"
        ? body.text
        : typeof body?.userText === "string"
          ? body.userText
          : "";
    const userText = explicitText.trim() || getLastUserText(body.messages);
    inputPreview = previewText(userText);
    debugLog(traceTag, "request_core_fields", {
      isPolicyCheck,
      isChatCompletions,
      stream,
      model,
      userTextLength: userText.length,
      xChatId: String(req.headers["x-chat-id"] || ""),
      xChatNew: String(req.headers["x-chat-new"] || ""),
      xUserType: userType,
      turnstileHeaderPresent: Boolean(String(req.headers[TURNSTILE_TOKEN_HEADER] || "").trim()),
    });

    if (!userText) {
      decision = "no_user_message";
      return json(
        res,
        400,
        isPolicyCheck
          ? {
              allowed: false,
              reason: "no_user_message",
              reply: "请先输入问题。",
              error: { message: "No user message found" },
            }
          : { error: { message: "No user message found" } }
      );
    }

    const internalKey = String(req.headers["x-internal-task-key"] || "").trim();
    const trustedInternal = INTERNAL_TASK_KEY && internalKey === INTERNAL_TASK_KEY;
    const bypassTurnstile = isPolicyCheck || trustedInternal;
    const bypassPolicy =
      !isPolicyCheck &&
      trustedInternal &&
      String(req.headers["x-policy-prechecked"] || "").trim() === "1";
    if (!bypassTurnstile) {
      const turnstileToken = getRequestTurnstileToken(req, body);
      debugLog(traceTag, "turnstile_verify_start", {
        tokenLength: turnstileToken.length,
        bypassTurnstile,
      });
      const turnstile = await verifyTurnstile({ token: turnstileToken, ip: clientIp });
      if (!turnstile.ok) {
        decision = `turnstile_${turnstile.reason}`;
        const message = `Turnstile verification failed: ${turnstile.reason}`;
        return json(
          res,
          403,
          isPolicyCheck
            ? {
                allowed: false,
                reason: `turnstile_${turnstile.reason}`,
                reply: "Turnstile 验证失败，请重新勾选后再发送。",
                error: { message },
              }
            : {
                error: { message },
              }
        );
      }
      debugLog(traceTag, "turnstile_verify_ok", { reason: turnstile.reason });
    }

    if (BLOCK_URL_INPUT && hasUrl(userText)) {
      decision = "blocked_url";
      if (isPolicyCheck) {
        return json(res, 200, {
          allowed: false,
          reason: "blocked_url",
          reply: URL_BLOCKED_REPLY,
        });
      }
      respondWithFixedReply({ res, stream, model, reply: URL_BLOCKED_REPLY });
      return;
    }

    if (!bypassPolicy) {
      const policy = await classifyInputPolicy(userText);
      if (!policy.allowed) {
        if (policy.source) {
          process.stdout.write(
            `[policy] blocked reason=${policy.reason} source=${policy.source}\n`
          );
        }
        decision = `blocked_${policy.reason}`;
        if (isPolicyCheck) {
          return json(res, 200, {
            allowed: false,
            reason: `blocked_${policy.reason}`,
            rawReason: policy.reason,
            reply: policy.reply,
            source: policy.source || "",
          });
        }
        respondWithFixedReply({ res, stream, model, reply: policy.reply });
        return;
      }
    } else {
      process.stdout.write("[policy] skipped via trusted precheck header\n");
    }

    if (isPolicyCheck) {
      decision = bypassPolicy ? "policy_check_ok_bypassed" : "policy_check_ok";
      debugLog(traceTag, "policy_check_return", { bypassPolicy, decision });
      return json(res, 200, {
        allowed: true,
        reason: "ok",
        reply: "",
      });
    }

    const sessionId = String(req.headers["x-chat-id"] || randomUUID());
    const isNewSession = String(req.headers["x-chat-new"] || "false") === "true";
    const finalPrompt = buildForcedPrompt(userText, userType);
    const requestCacheKey = cacheKey({ model, prompt: finalPrompt });
    const canUseCache = CACHE_ENABLED && isNewSession;
    if (canUseCache) {
      const cachedContent = readCache(requestCacheKey);
      if (cachedContent) {
        decision = "cache_hit";
        debugLog(traceTag, "cache_hit", { cacheKey: requestCacheKey, contentLength: cachedContent.length });
        return respondWithFixedReply({ res, stream, model, reply: cachedContent });
      }
      debugLog(traceTag, "cache_miss", { cacheKey: requestCacheKey });
    }

    if (stream) {
      decision = "ok_stream";
      writeOpenAiSseStart(res);
      const id = `chatcmpl-${randomUUID()}`;
      let rawAccumulated = "";
      let emittedLength = 0;
      let rawReasoning = "";
      let emittedReasoningLength = 0;

      await runCodexWithFallback({
        prompt: finalPrompt,
        chatId: sessionId,
        isNewSession,
        userType,
        traceTag,
        onTextChunk: (chunk) => {
          rawAccumulated += chunk;
          const redacted = redactSensitive(rawAccumulated);
          const delta = redacted.slice(emittedLength);
          if (!delta) {
            return;
          }
          emittedLength = redacted.length;
          writeOpenAiSseChunk(res, createChunk({ id, model, content: delta }));
        },
        onReasoningChunk: (chunk) => {
          rawReasoning += chunk;
          const redacted = redactSensitive(rawReasoning);
          const delta = redacted.slice(emittedReasoningLength);
          if (!delta) {
            return;
          }
          emittedReasoningLength = redacted.length;
          writeOpenAiSseChunk(res, createChunk({ id, model, reasoning: delta }));
        },
      });

      writeOpenAiSseChunk(res, createDoneChunk({ id, model }));
      debugLog(traceTag, "stream_done", {
        emittedLength,
        emittedReasoningLength,
      });
      return writeOpenAiSseDone(res);
    }

    const result = await runCodexWithFallback({
      prompt: finalPrompt,
      chatId: sessionId,
      isNewSession,
      userType,
      traceTag,
    });

    const content = redactSensitive(result.text);
    if (canUseCache && content) {
      writeCache(requestCacheKey, content);
    }
    decision = canUseCache ? "ok_json_cache_write" : "ok_json";
    debugLog(traceTag, "json_done", {
      decision,
      contentLength: content.length,
      threadId: result.threadId || "",
    });

    return json(res, 200, {
      id: `chatcmpl-${randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content,
          },
          finish_reason: "stop",
        },
      ],
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Proxy error";
    decision = `error:${previewText(message, 48)}`;
    if (res.headersSent) {
      try {
        res.write(
          `data: ${JSON.stringify({
            error: {
              message,
            },
          })}\n\n`
        );
        res.write("data: [DONE]\n\n");
      } catch {
        // ignore write failures on broken streams
      }
      res.end();
      return;
    }

    json(res, 500, { error: { message } });
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`[codex-openai-proxy] listening on http://${HOST}:${PORT}\n`);
});
