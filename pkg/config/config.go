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

// DefaultPorts 默认扫描端口列表（按命中率降序排列）。
//
// 调研依据（2025-06）：
//   - 8000: FastMCP / 官方 Python SDK 默认；绝大多数 Python MCP 服务器
//   - 3000: MCPHub / Firebase tools / MCP-Nest 默认
//   - 443/80: 生产环境反向代理
//   - 8080: FastMCP dev_server 默认；Skyvern UI
//   - 7860: Gradio MCP（HuggingFace 生态，数千 Space）+ Langflow 默认 ← 新增
//   - 3030: MCP-Nest（NestJS MCP 框架）所有示例默认端口 ← 新增
//   - 3001: Node.js 次级端口；ohcnetwork MCP
//   - 8443: HTTPS 非标准端口
//   - 5000: Python web 服务常用端口
//   - 4000/9000: 无 MCP 特定证据，保留但优先级最低
var DefaultPorts = []int{
	// Tier 1 — MCP 高频端口
	8000, 3000, 443, 80, 8080,
	// Tier 2 — 框架默认 / 次高频
	7860, 3030, 3001, 8443, 5000,
	// Tier 3 — 低频保留
	4000, 9000,
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
	"/api/v1/mcp",      // Langflow；brightbean-studio
	"/api/v1/mcp/sse",  // Langflow SSE 端点
	"/mcp-server",      // 教程推荐挂载前缀
	"/mcp-server/sse",  // 教程组合变体（FastAPI mount 示例）

	// T2 - 版本化 / 尾斜杠变体
	"/sse/",          // Starlette：不带尾斜杠会 307
	"/v1/mcp",        // 对外公共服务版本号
	"/mcp/messages/", // Azure Samples / Langflow 变体
	"/mcp/v1/messages",

	// T3 - 服务发现 / 健康检查（用于 fingerprint，命中即可确认）
	"/.well-known/mcp/server-card.json", // MCP 服务发现；Skyvern / react-server / mos
	"/.well-known/mcp",                  // MCP 状态端点
	"/mcp/health",                       // holaboss-ai/holaOS 健康检查
}

// SSELegacyPaths 这些路径需要用 HTTP+SSE legacy 协议探测（GET + 保持长连接）。
// 当 streamable HTTP probe 在这些路径失败时，应额外尝试 legacy SSE 握手。
var SSELegacyPaths = map[string]bool{
	"/sse":              true,
	"/mcp/sse":          true,
	"/mcp-server/sse":   true,
	"/sse/":             true,
	"/api/v1/mcp/sse":   true, // Langflow SSE 端点
	"/gradio_api/mcp/":  true, // Gradio 同时支持 SSE legacy 和 Streamable HTTP
}

// MCPAuthPaths 已知 MCP 特征路径集合，用于 auth-required 打分。
// 在此路径上收到 4xx 可加 1 分（联合其他信号判断）。
var MCPAuthPaths = map[string]bool{
	"/mcp": true, "/sse": true, "/messages": true, "/message": true,
	"/messages/": true, "/sse/": true,
	"/mcp/sse": true, "/mcp/messages": true, "/mcp/message": true,
	"/api/mcp": true, "/v1/mcp": true, "/api/v1/mcp": true,
	"/api/v1/mcp/sse": true,
	"/mcp-server": true, "/mcp-server/sse": true,
	"/gradio_api/mcp": true, "/gradio_api/mcp/": true,
	"/mcp/messages/": true,
}

// ── HTTP Server 头特征 ───────────────────────────────────────────────────────
// FilterHTTP 阶段用于提升候选优先级（命中则 priority=2）。

// MCPServerHints Server 响应头中出现这些字符串时，视为高优先级 MCP 候选。
var MCPServerHints = []string{
	"uvicorn",  // FastAPI / Python ASGI 默认服务器
	"fastapi",
	"fastmcp",
	"express",  // Node.js 最常见框架
	"fastify",
	"node",
	"python",
	"gunicorn", // Python WSGI 生产服务器
	"gradio",   // Gradio MCP（HuggingFace 生态）
	"langflow", // Langflow MCP
	"nestjs",   // MCP-Nest
}

// ── HTTPS 端口推断规则 ────────────────────────────────────────────────────────
// FilterHTTP 在未指定 scheme 时，根据端口推断协议。

// HTTPSPorts 这些端口默认使用 HTTPS。
var HTTPSPorts = map[int]bool{
	443:  true,
	8443: true,
}
