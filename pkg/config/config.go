// Package config centralises all tunable constants for AgentScan.
// Edit this file to add new endpoints, ports, or detection hints without
// touching scanner logic.
package config

// ── 扫描默认参数 ────────────────────────────────────────────────────────────

const (
	// DefaultTimeoutConnectMs TCP 连接超时（毫秒）。
	// 2000ms 兼顾国内（<50ms）和欧美（~200ms RTT）目标。
	// 如需更快扫描纯国内目标，可用 --timeout 500 覆盖。
	DefaultTimeoutConnectMs = 2000

	// DefaultConcurrency 最大并发 TCP 连接数。
	DefaultConcurrency = 500
)

// DefaultPorts MCP 默认扫描端口列表（按命中率降序排列）。
//
// 数据来源（2025-06 实测）：
//   Quake  app:"Model Context Protocol"（全球）: 8000, 8001, 443, 3000, 80
//   Quake  app:"Model Context Protocol" 中国:    8001, 8000, 3000, 11003, 8080
//   FOFA   header="MCP-Protocol-Version||MCP-Session-Id": 443, 80, 3000, 3001, 8080
//
//   - 8000:  全球 #1；Python SDK / FastMCP 默认
//   - 8001:  中国 #1 / 全球 #2；大量国内部署用此端口（之前误删，现加回）
//   - 443:   全球 #3 / FOFA #1；生产反向代理
//   - 3000:  全球 #4 / 中国 #3；MCPHub / Firebase / MCP-Nest
//   - 80:    全球 #5 / FOFA #2；生产反向代理
//   - 8080:  中国 #5 / FOFA #5；FastMCP dev_server
//   - 3001:  FOFA #4；Node.js 次级端口
//   - 11003: 中国 #4；国内实测发现，来源待定
//   - 7860:  Gradio MCP / Langflow（HuggingFace 生态）
//   - 3030:  MCP-Nest（NestJS 框架）默认
//   - 8443:  HTTPS 非标准端口
//   - 5000:  Python web 常用端口
//   - 4000/9000: 无 MCP 特定证据，保留但优先级最低
var DefaultPorts = []int{
	// Tier 1 — 实测高频（Quake / FOFA 榜单前列）
	8000, 8001, 443, 3000, 80, 8080, 3001,
	// Tier 2 — 实测发现 + 框架默认
	11003, 7860, 3030, 8443, 5000,
	// Tier 3 — AI/云原生生态补充
	8888,  // Jupyter Notebook / Gradio 备用（AI 工具链高频）
	8787,  // Cloudflare Workers wrangler dev 本地默认
	5001,  // Flask macOS 替代（AirPlay 占用 5000）
	4000, 9000,
	// Tier 4 — AI Gateway 专用端口（实测：OmniRoute/Routiform 中国部署）
	20128, // OmniRoute AI Gateway 默认端口（Quake/实测大量命中）
	20888, // OmniRoute/Routiform 变体端口（实测命中）
	9001,  // OmniRoute 变体；Portainer 也用此端口
	3002,  // OmniRoute 变体；Next.js dev 副端口
	// Tier 5 — 通用补充（低优先级，无 MCP 特定证据）
	8081,  // 常见反向代理次级端口
	10000, // 通用服务端口
}

// A2ADefaultPorts A2A 默认扫描端口列表。
//
// A2A spec 未约定专用端口，部署以标准 web 端口为主。
// 数据来源：A2A 规范参考实现 + 实测已知 A2A 服务。
//
//   - 80/443:  标准 HTTP/HTTPS；生产部署首选
//   - 8080/8443: 非标准 HTTP/HTTPS；开发 / 反向代理常见
//   - 3000/8000: Node.js / Python 框架开发默认端口
//   - 8001/3001/5000: 次级开发端口
//   - 4010:  EasyClaw A2A marketplace 专用端口
//   - 9000:  通用服务端口
var A2ADefaultPorts = []int{
	// Tier 1 — 标准 web 端口
	80, 443, 8080, 8443,
	// Tier 2 — 框架默认开发端口
	3000, 8000, 8001, 3001, 5000,
	// Tier 3 — AI 生态特定端口
	7860,  // Gradio（HuggingFace 生态，A2A agent 常见宿主）
	8501,  // Streamlit 默认端口
	8888,  // Jupyter Notebook / Gradio 备用
	4010,  // EasyClaw A2A marketplace
	// Tier 4 — 通用补充
	8081, 9000, 9001, 10000,
	// Tier 5 — AI Gateway（OmniRoute 等中国部署，A2A 可能共用）
	20128, 20888,
}

// ── MCP 端点字典 ─────────────────────────────────────────────────────────────
// 探测顺序即优先级：T0 > T1 > T2 > T3。
// 并行模式下顺序决定结果优先级（index 越小越优先返回）。

// MCPEndpoints 所有要探测的 HTTP 路径。
//
// 调研依据（2025-06，50+ 真实 GitHub 仓库）：
//   - /mcp:             Streamable HTTP 规范路径；FastMCP / Python SDK / TS SDK 一致采用
//   - /sse:             SSE legacy GET 端点；FastMCP / Python SDK 默认
//   - /messages/:       Python SDK SseServerTransport 默认（带尾斜杠）
//   - /messages:        TS SDK 社区实现常见（无尾斜杠）
//   - /message:         官方 TS SDK "everything" server / Firebase tools（单数）
//   - /gradio_api/mcp:  Gradio MCP；HuggingFace 上数千 Space 暴露此路径 ← 新增
//   - /gradio_api/mcp/: 同上带尾斜杠变体 ← 新增
//   - /api/v1/mcp/sse:  Langflow SSE 端点 ← 新增
//   - /mcp/messages/:   Azure Samples / Langflow 变体 ← 新增
//   - /.well-known/mcp/server-card.json: MCP 服务发现（多框架采用） ← 新增
//   - 已删除 /jsonrpc /rpc：零 MCP 使用证据，纯噪音
var MCPEndpoints = []string{
	// T0 - 核心（官方规范 / SDK 默认，覆盖 99% 标准部署）
	"/mcp",       // Streamable HTTP 规范路径；FastMCP / Python SDK / TS SDK
	"/sse",       // SSE legacy GET 端点；FastMCP / Python SDK
	"/messages/", // Python SDK SseServerTransport 默认（带尾斜杠）
	"/messages",  // TS SDK 社区实现（无尾斜杠）
	"/message",   // 官方 TS SDK "everything" server；Firebase tools（单数）
	"/",          // 极简部署直接挂根路径

	// T1 - 框架挂载 / 大型生态
	"/gradio_api/mcp",  // Gradio MCP；HuggingFace 数千 Space
	"/gradio_api/mcp/", // 同上带尾斜杠
	"/mcp/sse",         // MCP router 挂 /mcp 下的 SSE 子路由
	"/mcp/messages",    // MCP router 挂 /mcp 下的消息子路由
	"/mcp/message",     // 同上单数变体；Spring AI MetricsHub
	"/api/mcp",         // Spring AI Streamable HTTP；企业 RESTful 规范
	"/api/mcp/sse",     // /api/mcp 下的 SSE 子路由
	"/api/v1/mcp",      // Langflow；brightbean-studio
	"/api/v1/mcp/sse",  // Langflow SSE 端点
	"/mcp-server",      // 教程推荐挂载前缀
	"/mcp-server/sse",  // 教程组合变体（FastAPI mount 示例）
	"/agent/mcp",       // agent 前缀挂载 MCP

	// T2 - 版本化 / 尾斜杠变体
	"/mcp/",          // 带尾斜杠变体（部分框架重定向）
	"/sse/",          // Starlette：不带尾斜杠会 307
	"/v1/mcp",        // 对外公共服务版本号
	"/mcp/v1",        // MCP 版本化子路由
	"/mcp/messages/", // Azure Samples / Langflow 变体
	"/mcp/v1/messages",

	// T3 - 服务发现 / 健康检查（用于 fingerprint，命中即可确认）
	"/.well-known/mcp/server-card.json", // MCP 服务发现；Skyvern / react-server / mos
	"/.well-known/mcp",                  // MCP 状态端点
	"/.well-known/mcp.json",             // MCP 服务发现 JSON 变体
	"/mcp/health",                       // holaboss-ai/holaOS 健康检查
}

// SSELegacyPaths 这些路径需要用 HTTP+SSE legacy 协议探测（GET + 保持长连接）。
// 当 streamable HTTP probe 在这些路径失败时，应额外尝试 legacy SSE 握手。
var SSELegacyPaths = map[string]bool{
	"/sse":              true,
	"/mcp/sse":          true,
	"/mcp-server/sse":   true,
	"/sse/":             true,
	"/api/mcp/sse":      true, // /api/mcp 下的 SSE 子路由
	"/api/v1/mcp/sse":   true, // Langflow SSE 端点
	"/gradio_api/mcp/":  true, // Gradio 同时支持 SSE legacy 和 Streamable HTTP
}

// MCPAuthPaths 已知 MCP 特征路径集合，用于 auth-required 打分。
// 在此路径上收到 4xx 可加 1 分（联合其他信号判断）。
var MCPAuthPaths = map[string]bool{
	"/mcp": true, "/mcp/": true, "/sse": true, "/messages": true, "/message": true,
	"/messages/": true, "/sse/": true,
	"/mcp/sse": true, "/mcp/messages": true, "/mcp/message": true,
	"/api/mcp": true, "/api/mcp/sse": true,
	"/v1/mcp": true, "/mcp/v1": true, "/api/v1/mcp": true,
	"/api/v1/mcp/sse": true,
	"/mcp-server": true, "/mcp-server/sse": true,
	"/gradio_api/mcp": true, "/gradio_api/mcp/": true,
	"/mcp/messages/": true,
	"/agent/mcp": true,
}

// ── HTTP 请求头 ───────────────────────────────────────────────────────────────

// UserAgent 所有 HTTP 请求统一使用的 User-Agent，模拟主流浏览器避免被过滤。
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// ── HTTP Server 头特征 ───────────────────────────────────────────────────────
// FilterHTTP 阶段用于提升候选优先级（命中则 priority=2）。

// MCPServerHints Server 响应头中出现这些字符串时，视为高优先级 MCP 候选。
var MCPServerHints = []string{
	// Python 生态
	"uvicorn",    // FastAPI / Python ASGI 默认服务器
	"fastapi",
	"fastmcp",
	"gunicorn",   // Python WSGI 生产服务器
	"starlette",  // FastAPI 底层框架（少数场景暴露）
	"hypercorn",  // Python ASGI 替代服务器（Quart 默认）
	"werkzeug",   // Flask 开发服务器
	"python",
	// Node.js / JS Runtime 生态
	"express",    // Node.js 最常见框架
	"fastify",
	"node",
	"hono",       // Cloudflare Workers / Deno 生态流行框架
	"deno",       // Deno runtime
	"bun",        // Bun runtime
	"nestjs",     // MCP-Nest
	// 专有 MCP 生态
	"gradio",     // Gradio MCP（HuggingFace 生态）
	"langflow",   // Langflow MCP
	// 其他语言
	"kestrel",    // ASP.NET Core 默认服务器（C# MCP SDK）
}

// ── HTTPS 端口推断规则 ────────────────────────────────────────────────────────
// FilterHTTP 在未指定 scheme 时，根据端口推断协议。

// HTTPSPorts 这些端口默认使用 HTTPS。
var HTTPSPorts = map[int]bool{
	443:  true,
	8443: true,
}

// ── A2A 路径字典 ──────────────────────────────────────────────────────────────
// buildA2ACardPaths 使用此列表作为 well-known card 发现的基础路径。
// 顺序即优先级：标准路径在前，非标准路径在后。

// A2ACardPaths A2A agent card 发现路径列表。
//
//   - /.well-known/agent-card.json: A2A spec 标准路径（官方规范）
//   - /.well-known/agent.json:      A2A legacy 路径（早期实现）
//   - /agent.json:                  根路径变体（无 .well-known 前缀的极简部署）
var A2ACardPaths = []string{
	"/.well-known/agent-card.json", // A2A spec 标准（官方规范）
	"/.well-known/agent.json",      // A2A legacy（早期实现）
	"/agent.json",                  // 根路径变体（极简部署）
}

// ── LLM 默认端口 ────────────────────────────────────────────────────────────
// LLM Inference API 默认扫描端口列表。
//
// P0 — 框架默认端口（最高命中率）：
//
//	11434: Ollama 默认
//	8000:  vLLM / SGLang / FastChat 默认
//	8080:  LocalAI / 通用 HTTP
//	3000:  LiteLLM 默认
//	1234:  LM Studio 默认
//	4000:  LiteLLM proxy 备选
//
// P1 — 次要框架端口：
//
//	9997:  Xinference 默认
//	30000: SGLang 备选
//	5001:  LocalAI 备选
//	4891:  LiteLLM 备选
//	23333: LMDeploy 默认
//	21001: FastChat controller
//	21002: FastChat model worker
//	7860:  Gradio-based UIs（Xinference web）
//
// P2 — 多实例/其他：
//
//	8001, 8002: vLLM 多实例
//	5000:  通用 Python
//	7080:  LMDeploy 备选
//	20128: AI gateway
//	11435-11440: Ollama 集群范围
var LLMDefaultPorts = []int{
	// P0
	11434, 8000, 8080, 3000, 1234, 4000,
	// P1
	9997, 30000, 5001, 4891, 23333, 21001, 21002, 7860,
	// P2
	8001, 8002, 5000, 7080, 20128,
	11435, 11436, 11437, 11438, 11439, 11440,
}
