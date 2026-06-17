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

// DefaultPorts 默认扫描端口列表。
// 覆盖主流 MCP 部署场景：Web 标准端口 + 常见开发端口。
var DefaultPorts = []int{
	80, 443,
	8000, 8080, 8443,
	3000, 3001,
	4000, 5000,
	9000,
}

// ── MCP 端点字典 ─────────────────────────────────────────────────────────────
// 探测顺序即优先级：T0 > T1 > T2 > T3。
// 并行模式下顺序决定结果优先级（index 越小越优先返回）。

// MCPEndpoints 所有要探测的 HTTP 路径。
var MCPEndpoints = []string{
	// T0 - 核心（官方规范 / SDK 默认）
	"/mcp",      // Streamable HTTP 官方推荐；FastMCP 默认
	"/sse",      // 旧版 HTTP+SSE 核心 GET 端点
	"/messages", // 旧版 POST 消息端点；Python/TS SDK 默认
	"/message",  // C# SDK 硬编码默认；TS SDK 示例混用
	"/",         // 极简部署直接挂根路径

	// T1 - 框架挂载组合（/mcp 前缀最常见）
	"/mcp/sse",        // MCP router 挂 /mcp 下，SSE 子路由
	"/mcp/messages",   // MCP router 挂 /mcp 下，消息子路由
	"/mcp/message",    // 同上，单数变体
	"/api/mcp",        // 企业级 RESTful 规范
	"/mcp-server",     // 多篇教程推荐的挂载前缀
	"/mcp-server/sse", // 教程组合变体（FastAPI mount 示例）

	// T2 - 版本化 / 尾斜杠
	"/sse/",         // Python Starlette：不带尾斜杠会 307，带斜杠才命中
	"/messages/",    // 同上，Python SDK 内部定义为 /messages/
	"/v1/mcp",       // 对外公共服务带版本号
	"/api/v1/mcp",   // 版本化 + API 前缀组合
	"/mcp/messages/",
	"/mcp/v1/messages",

	// T3 - 泛化 JSON-RPC（低频，自研框架）
	"/jsonrpc",
	"/rpc",
}

// MCPAuthPaths 已知 MCP 特征路径集合，用于 auth-required 打分。
// 在此路径上收到 4xx 可加 1 分（联合其他信号判断）。
var MCPAuthPaths = map[string]bool{
	"/mcp": true, "/sse": true, "/messages": true, "/message": true,
	"/mcp/sse": true, "/mcp/messages": true, "/mcp/message": true,
	"/api/mcp": true, "/v1/mcp": true, "/api/v1/mcp": true,
	"/mcp-server": true, "/mcp-server/sse": true,
	"/sse/": true, "/messages/": true,
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
}

// ── HTTPS 端口推断规则 ────────────────────────────────────────────────────────
// FilterHTTP 在未指定 scheme 时，根据端口推断协议。

// HTTPSPorts 这些端口默认使用 HTTPS。
var HTTPSPorts = map[int]bool{
	443:  true,
	8443: true,
}
