[English](README.md) | 中文

# AgentScan

**AI Agent 协议暴露面扫描器** — 发现网络上未经认证的 Model Context Protocol 服务器，枚举其工具、资源和提示词，并检测蜜罐。

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 背景

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) 将 AI Agent 与外部工具和数据源连接起来。由于规范中认证是**可选的**，大量部署的服务器处于完全开放状态。

**问题规模（2025–2026）：**

| 来源 | 日期 | 发现的暴露服务器数 |
|------|------|------------------|
| Trend Micro | 2025-07 | 492 |
| Bitsight TRACE | 2025-12 | ~1,000 |
| Trend Micro（更新）| 2026-04 | 1,467 |
| arXiv 2605.22333 | 2026-05 | **7,973**（40.55% 无认证）|
| GuidePoint Security | 2026-06 | **2,305**（62,000 个端点中）|

真实危害包括：未经认证访问 Kubernetes 集群、CRM 数据库，以及工具描述中嵌入的 AWS 凭证。

---

## 为什么叫 AgentScan？

MCP 是起点，但 AI Agent 生态远不止一个协议。这个名字反映的是这个工具的方向。

AI Agent 的通信并没有统一标准，当前的格局是多个协议并存，各自有独立的发现端点和暴露特征：

| 协议 | 主导方 | 定位 | 发现端点 |
|------|--------|------|---------|
| **MCP** | Anthropic | Agent ↔ 工具 | JSON-RPC `initialize` 握手 |
| **A2A** | Google / Linux Foundation | Agent ↔ Agent | `/.well-known/agent.json` |
| **ACP** | IBM / BeeAI | Agent ↔ Agent（REST 风格）| `/.well-known/agent.json` |
| **ChatGPT Plugin** | OpenAI | LLM ↔ 外部服务 | `/.well-known/ai-plugin.json` |

这些协议都面临同一个根本问题：认证是可选的或根本没有，而发现端点天然设计为公开可达。"AgentScan" 覆盖的是整个暴露面，而不只是 MCP。

### 协议支持路线图

- [x] MCP（Streamable HTTP + 旧版 HTTP+SSE）
- [ ] A2A — `/.well-known/agent.json`、`/.well-known/agent-card.json`、`A2A-Version` 响应头
- [ ] ACP — `/.well-known/agent.json`（通过 `agentId` / `runs` 字段与 A2A 区分）
- [ ] ChatGPT Plugin — `/.well-known/ai-plugin.json`（存量部署量大，`"auth": {"type": "none"}` 普遍）

---

## 功能特性

- **主动 CIDR/IP/域名扫描** — 无需 Shodan，无确认提示，直接扫描
- **多种输入格式** — IP、CIDR、IP 范围（`1.1.1.1-2.2.2.3`）、域名、`host:port`、URL（`https://host/path`）
- **精准 MCP 指纹识别** — 三层加权评分（≥0.65 确认为 MCP），排除 LSP 和通用 JSON-RPC 误报
- **SNI 感知 HTTPS** — 正确处理需要 TLS SNI（Server Name Indication）的反向代理服务器
- **URL 路径保留** — `https://host/custom-mcp` 优先探测 `/custom-mcp`
- **双传输协议支持** — Streamable HTTP（当前规范）和旧版 HTTP+SSE（2024-11-05，仍有 1,227+ 台服务器在用）
- **完整暴露面枚举** — 工具、资源、资源模板、提示词（全部只读，从不调用 `tools/call`）
- **蜜罐检测 (Honeypot Detection)** — 通过 Session ID 一致性和协议版本验证识别诱饵服务器
- **JSON + 终端输出** — 机器可读报告，支持管道（`--format json 2>/dev/null | jq`）
- **`NO_COLOR` 支持** — 遵循 [no-color.org](https://no-color.org/) 标准

---

## 快速开始

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
go build -o agentscan .

# 扫描所有已支持的协议
./agentscan scan api.example.com

# 只扫描 MCP
./agentscan mcp api.example.com

# 扫描子网
./agentscan mcp 192.168.1.0/24

# 扫描 IP 范围
./agentscan mcp 10.0.0.1-10.0.0.50

# 从目标文件扫描
./agentscan mcp -f targets.txt

# 直接扫描指定 MCP URL
./agentscan mcp https://api.example.com/mcp

# 将结果保存为 JSON
./agentscan mcp 10.0.0.0/24 --format json -o results.json

# 使用 -t 指定多个目标
./agentscan mcp -t 192.168.1.0/24 -t api.example.com
```

> **无确认提示。** AgentScan 立即开始扫描。您有责任只扫描已获授权的系统。

---

## 构建

```bash
# 本机二进制（当前 OS/架构）
powershell -ExecutionPolicy Bypass -File build.ps1   # Windows
./build.sh                                            # Linux/macOS

# 交叉编译
./build.sh linux amd64
./build.sh darwin arm64
powershell -ExecutionPolicy Bypass -File build.ps1 -OS linux -Arch amd64
```

输出文件：`dist/agentscan`（Windows 为 `dist/agentscan.exe`）。

---

## 用法

### 命令结构

```
agentscan <命令> [选项] [目标...]

命令：
  mcp     扫描暴露的 MCP（Model Context Protocol）服务器
  scan    扫描所有已支持的协议（依次运行所有协议扫描器）
```

每个协议命令都有针对该协议特性调优的专属 flag，目标输入、输出格式、TCP 扫描等公共 flag 在所有命令间共享。

---

### `agentscan mcp` — MCP 扫描器

```
agentscan mcp [选项] [目标...]

目标选项：
  -t, --target value     目标（IP、CIDR、IP 范围、域名、host:port、URL），可重复使用
  -f, --file value       目标文件（每行一个，支持 # 注释）

扫描选项：
  --ports value          逗号分隔的端口列表
                         （默认：8000,8001,443,3000,80,8080,3001,11003,7860,3030,8443,5000,8888,8787,5001,4000,9000）
  --threads value, -T    最大并发 TCP 连接数（默认：500）
  --mcp-threads value    最大并发 MCP 探测连接数（默认：50）
  --timeout value        TCP 连接超时毫秒（默认：500）
                         HTTP 超时 = timeout × 10，MCP 超时 = timeout × 20
  --skip-port-scan       跳过 TCP 端口扫描，将所有输入视为已开放的 IP:Port
  --exclude-honeypots    从结果中排除疑似蜜罐

输出选项：
  -o, --output value     JSON 输出文件路径
  --format value         terminal | json（默认：terminal）
  --verbose, -v          按阶段输出进度日志：开放端口、探测目标、响应时间
  --verbose-raw          在 JSON 中包含原始 initialize 响应（每台服务器增加约 2 KB）
  --no-color, --Cn       禁用 ANSI 颜色（也可设置 NO_COLOR 环境变量）
```

---

### `agentscan scan` — 全协议扫描

```
agentscan scan [选项] [目标...]
```

对同一批目标依次运行所有协议扫描器，接受所有协议专属 flag 的并集。输出按协议打标签（`[MCP]`、`[A2A]` 等）。

> 当前等价于 `mcp` — 后续协议实现后会逐步加入。

### 默认端口

端口选择基于真实扫描数据的实证：

| 层级 | 端口 | 数据来源 |
|------|------|---------|
| Tier 1 — 真实高频 | `8000, 8001, 443, 3000, 80, 8080, 3001` | Quake 全球 Top + FOFA `header="MCP-Protocol-Version"` |
| Tier 2 — 框架默认 | `11003, 7860, 3030, 8443, 5000` | Quake 国内 Top（11003 突出）；Gradio（7860）|
| Tier 3 — 低频长尾 | `8888, 8787, 5001, 4000, 9000` | 语料库中观察到的长尾分布 |

### 目标格式

```
# 单个 IP
10.0.0.1

# CIDR
10.0.0.0/24

# IP 范围
10.0.0.1-10.0.0.50
192.168.1.1-255        # 简写：仅指定末段

# 域名
api.example.com

# 域名加指定端口
api.example.com:8080

# URL — 路径会被保留并优先探测
https://api.example.com/mcp
http://internal-host:8000/api/mcp

# 文件（-f targets.txt）
10.0.0.1
10.0.0.2:8000
192.168.1.0/24
# 这是注释
api.example.com
```

### 参数位置

Flag 可以出现在目标**前面或后面**：

```bash
# 以下三种写法等价：
agentscan mcp 192.168.1.0/24 --format json
agentscan mcp --format json 192.168.1.0/24
agentscan mcp -t 192.168.1.0/24 --format json -o out.json
```

---

## 最佳实践

AgentScan 是 **AI Agent 协议暴露面扫描器**，不是通用端口扫描器。根据目标规模选择合适的工作方式。

### 场景 1：测绘平台导出（最常见）

从 Quake、FOFA 或 Shodan 导出 IP:port 列表时，端口已确认开放，重跑 TCP 扫描只会浪费时间和连接数。用 `--skip-port-scan` 直接进入 MCP 探测阶段。

```bash
# 从 Quake/FOFA 导出 IP:port 列表后，用 AgentScan 验证
agentscan mcp -f quake_results.txt --skip-port-scan --mcp-threads 200 --format json -o verified.json
```

`--skip-port-scan` 完全跳过阶段 1，把文件中每一行都视为已开放的端点。对预过滤输入来说速度约快 3 倍，因为省去了扫描阶段的 TCP 连接开销。

### 场景 2：masscan + AgentScan 流水线（互联网规模）

面对大段 CIDR，让 masscan 承担原始 TCP 吞吐，再把开放端口喂给 AgentScan 做 MCP 层分析。两者优势互补：masscan 针对每秒报文数优化，AgentScan 针对协议正确性优化。

```bash
# 第一步：masscan TCP 扫描，找出开放端口
masscan 1.0.0.0/8 -p 8000,8001,443,3000,80,8080,3001,11003 --rate 100000 -oL open_ports.txt

# 第二步：将 masscan -oL 输出转换为 host:port 列表
grep "open" open_ports.txt | awk '{print $4":"$3}' > targets.txt

# 第三步：AgentScan 处理 MCP 指纹识别、枚举、蜜罐检测
agentscan mcp -f targets.txt --skip-port-scan --mcp-threads 200 --timeout 3000 --format json -o results.json
```

### 场景 3：内网网段扫描

低延迟内网可以承受更短的超时和更高的并发。把 `--timeout` 压到 200ms，把 `--threads` 拉高以跑满本地链路带宽。

```bash
# 单个子网
agentscan mcp 192.168.1.0/24 --timeout 200 --threads 2000 --mcp-threads 100

# 多个网段
agentscan mcp -t 10.0.0.0/8 -t 172.16.0.0/12 --timeout 200 --threads 2000 --mcp-threads 200 --format json -o intranet.json
```

> **注意：** `/8` 对应 1600 万个 IP，乘以 17 个默认端口约等于 2.72 亿次 TCP 探测。建议用 `--ports` 限制为网络中实际可能出现的两三个端口。

### 场景 4：单目标 / 已知 URL 精准探测

当测绘结果给出了具体 URL 时，可以跳过所有扫描阶段直接进入 MCP 探测。AgentScan 会保留 URL 路径并优先探测。

```bash
# 直接指定 URL — 阶段 1 和 2 自动跳过
agentscan mcp https://api.example.com/mcp

# 多个已知主机，开启详细输出
agentscan mcp -t host:8000 -t host:3000 --skip-port-scan --verbose
```

### 场景 5：CI / 自动化流水线

JSON 输出走 stdout，所有进度信息走 stderr，可以直接管道给 `jq` 而无需过滤噪音。

```bash
agentscan mcp 10.0.0.0/24 --format json -o results.json 2>/dev/null

# 筛选无认证服务器，打印 IP、端口和工具数
cat results.json | jq '.results[] | select(.no_auth == true) | {ip, port, tool_count}'
```

退出码始终为 `0`（无论是否有发现）。非零退出码表示致命错误（参数错误、目标无法解析等）。

---

## 输出

### 终端（默认）

```
[MCP] 1.2.3.4:8000  /mcp  streamable_http  v=2025-06-18  no-auth
      server="my-mcp/1.0"  tools=5  resources=2  res_templates=1  prompts=3

[MCP] 203.0.113.10:3000  /sse  http_sse_legacy  v=2024-11-05  no-auth
      server="internal-tools/2.1"  tools=4  resources=0  res_templates=0  prompts=0
      [HONEYPOT] score=60  signals: invalid_version_accepted:9999-99-99, session_id_identical:abc123

=== AgentScan Summary ===
协议      服务器数  未认证  蜜罐
MCP       2         2       1
─────────────────────────────
合计      2         2       1
  Auth-required   : 0
  Tools exposed   : 9
  Resources       : 2
  Res templates   : 0
  Prompts         : 3
```

进度和警告输出到 **stderr**；JSON 结果输出到 **stdout**，支持管道：

```bash
agentscan mcp 10.0.0.0/24 --format json 2>/dev/null | jq '.results[].server_name'
```

### JSON

```json
{
  "version": "1.0",
  "summary": {
    "total": 2,
    "unauthenticated": 2,
    "auth_required": 0,
    "honeypots": 0,
    "total_tools": 34,
    "total_resources": 0,
    "total_resource_templates": 0,
    "total_prompts": 0
  },
  "results": [
    {
      "ip": "203.0.113.42",
      "port": 443,
      "url": "https://203.0.113.42:443",
      "endpoint": "/mcp",
      "transport": "streamable_http",
      "protocol_version": "2025-06-18",
      "no_auth": true,
      "server_name": "Binance Square Publisher",
      "server_version": "1.27.2",
      "tool_count": 1,
      "tools": [{"name": "publish_article", "description": "..."}],
      "resource_count": 2,
      "resources": [{"uri": "file:///data/config", "name": "config", "mimeType": "application/json"}],
      "resource_template_count": 0,
      "resource_templates": [],
      "prompt_count": 0,
      "prompts": [],
      "honeypot": {"suspected": false, "score": 0},
      "scan_time": "2026-06-17T12:00:00Z",
      "response_time_ms": 142,
      "tls_enabled": true
    }
  ]
}
```

---

## 工作原理

```
输入（IP / CIDR / IP 范围 / 域名 / URL / 文件）
  │
  ▼  目标解析
     域名解析为 IP，保留 hostname 用于 SNI
     保留 URL 路径（如 /mcp）供优先探测
  │
  ▼  阶段 1：TCP 端口扫描   [可用 --skip-port-scan 跳过]
     端口（17 个）：8000 8001 443 3000 80 8080 3001 11003 7860
                   3030 8443 5000 8888 8787 5001 4000 9000
     并发 goroutine，默认 500ms 连接超时
  │
  ▼  阶段 2：HTTP 筛选
     并发 GET /，读取 Server 和 Content-Type 响应头
     提前丢弃非 HTTP 响应，减少 MCP 探测压力
  │
  ▼  阶段 3：MCP 探测       （双传输协议，--mcp-threads 并发）
     探测 25 条端点路径：/mcp, /sse, /messages/, /gradio_api/mcp,
       /api/v1/mcp/sse, /.well-known/mcp/server-card.json, ...
     SSE 路径：/sse, /mcp/sse, /mcp-server/sse, /sse/,
               /api/v1/mcp/sse, /gradio_api/mcp/
     先发送 initialize，再发 notifications/initialized，然后才发请求
     指纹评分：
       protocolVersion 存在              +0.2
       MCP 特有 capabilities key         +0.3
       serverInfo.name 存在              +0.1
       检测到 LSP capabilities        → 分数归零，排除
     ≥ 0.65 = 确认为 MCP
  │
  ▼  阶段 4：暴露面枚举     （并行，只读）
     tools/list                → MCPTool    （name, description, inputSchema）
     resources/list            → MCPResource （uri, name, description, mimeType）
     resources/templates/list  → MCPResourceTemplate （uriTemplate, name, description）
     prompts/list              → MCPPrompt  （name, description）
  │
  ▼  阶段 5：蜜罐检测（2 个信号）
  │
  ▼  输出：终端（进度 → stderr）/ JSON（结果 → stdout）
```

---

## 蜜罐检测 (Honeypot Detection)

AgentScan 基于 Bitsight 对 1,100+ 蜜罐的分析，使用两个信号来识别诱饵服务器：

| 信号 | 分值 | 说明 |
|------|------|------|
| `invalid_version_accepted` | +20 | 服务器接受 `protocolVersion: "9999-99-99"` 且不报错（规范要求拒绝或返回 `-32602`）|
| `session_id_identical` | +40 | 两次独立的 `initialize` 调用返回相同的 `MCP-Session-Id`（规范要求全局唯一）|

总分 ≥ 40 → `suspected_honeypot: true`（显示在输出中，默认不过滤；使用 `--exclude-honeypots` 可排除）。

---

## 互联网测绘（Shodan / FOFA / ZoomEye）

以下查询语句仅用于**安全研究目的**，可在各测绘平台上定位公开暴露的 MCP 服务器。未经授权请勿扫描他人系统。

### Shodan

```
# 最高精度 — MCP 专有 HTTP 响应头
"MCP-Protocol-Version"

# 响应体中的协议版本字符串
"protocolVersion" "2025-11-25"
"protocolVersion" "2025-06-18"
"protocolVersion" "2024-11-05"

# serverInfo 字段（MCP initialize 响应独有）
"serverInfo" "protocolVersion"

# 端口 + 协议组合
port:8000 "jsonrpc" "tools"
port:3000 "text/event-stream" "jsonrpc"
port:8080 "text/event-stream" "mcp"

# 框架指纹
"uvicorn" "mcp"
"fastmcp"
http.title:"MCP Server"
```

### FOFA

> **推荐用于国内目标** — 对 WAF 后方资产的覆盖显著优于 Shodan。

```
# MCP 专有响应头（精度最高）
header="MCP-Protocol-Version"
header="MCP-Session-Id"

# 正文指纹
body="protocolVersion" && body="serverInfo" && body="capabilities"
body="tools/list" && body="jsonrpc"

# SSE 传输
header="text/event-stream" && body="jsonrpc" && body="mcp"

# 框架指纹
header="uvicorn" && body="mcp"
body="fastmcp"
title="MCP Server"
```

### ZoomEye

```
http.header="MCP-Protocol-Version"
http.header="text/event-stream" +http.body="jsonrpc" +http.body="protocolVersion"
http.header.server="uvicorn" +http.body="mcp"
```

### Censys

> Censys 仅索引 HTTP 响应体的前 **2 KB**，MCP `initialize` 响应通常超过此限制，正文搜索漏报率高，建议仅使用响应头搜索。

```
services.http.response.headers: (key="Content-Type" and value="text/event-stream")
services.http.response.body: "serverInfo"
```

**平台选型：**

| 平台 | 适用场景 | 备注 |
|------|---------|------|
| **Shodan** | 境外目标 | 行业标准，MCP 社区使用最广泛 |
| **FOFA** | 国内目标 | 覆盖更全面，WAF 穿透能力更强 |
| ZoomEye | 辅助验证 | 正文搜索能力较好 |
| Censys | 仅响应头搜索 | 2 KB 正文限制导致高漏报率 |

---

## 架构

```
internal/
  sseutil/       SSE 解析工具（ParseFirstMessage, ParseEndpointEvent）
  version/       通过 -ldflags 注入编译时版本信息

pkg/
  models/        数据结构（MCPServer, MCPTool, MCPResource,
                   MCPResourceTemplate, MCPPrompt, ScanConfig, HoneypotResult）
  target/        输入解析（IP、CIDR、范围、域名、URL）
  scanner/
    port.go      TCP 端口扫描（goroutine + semaphore）
    http_filter  HTTP 候选筛选（并发，SNI 感知）
    mcp_probe    MCP 指纹识别（三层评分，双传输协议，
                   25 路径字典，notifications/initialized 握手）
    enum.go      暴露面枚举：tools/list、resources/list、
                   resources/templates/list、prompts/list
    pipeline.go  五阶段流水线编排 + RunScan 入口
  analysis/
    honeypot.go  蜜罐检测（2 个信号）
  output/
    terminal.go  ANSI 终端输出（支持 NO_COLOR）
    json.go      结构化 JSON 报告
```

---

## 法律与伦理

> **本工具仅供授权安全测试和研究使用。**  
> 未经许可扫描他人系统可能违反所在地的计算机欺诈和滥用相关法律。

- AgentScan 只调用 `tools/list`、`resources/list`、`resources/templates/list` 和 `prompts/list`，从不调用 `tools/call`，也不向服务器写入任何内容
- 发现暴露服务器后，请遵循负责任披露原则：通知所有者，给予 90 天修复时间后再公开披露
- 工具启动后立即开始扫描，无确认提示。您有责任只扫描已获授权的目标。

---

## 相关研究

| 来源 | 核心发现 |
|------|---------|
| [arXiv:2605.22333](https://arxiv.org/abs/2605.22333)（2026-05）| 发现 7,973 台在线服务器；40.55% 无认证；使用 FOFA+Shodan 扫描 |
| [arXiv:2510.16558](https://arxiv.org/abs/2510.16558)（DSN 2026）| 两阶段攻击面模型；67,057 台中 833 台存在漏洞 |
| [arXiv:2601.17549](https://arxiv.org/abs/2601.17549) | 协议版本降级漏洞；攻击成功率提升 23–41% |
| [Bitsight TRACE](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities)（2025-12）| ~1,000 台暴露；发现 1,100+ 固定 Session ID 蜜罐 |
| [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud)（2026-04）| 1,467 台暴露；AWS/Azure MCP 服务器存在 CVSS 9.8 漏洞 |
| [GuidePoint Security](https://www.guidepointsecurity.com/blog/mcp-deployment-security-ai-ai-ai/)（2026-06）| 62,000 个探测端点中发现 2,305 台暴露服务器 |

---

## 许可证

MIT — 详见 [LICENSE](LICENSE)

---

## 免责声明

AgentScan 仅供**授权安全测试和研究**使用。  
作者对因滥用本工具造成的任何损失或损害不承担责任。
