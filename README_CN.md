[English](README.md) | 中文

# AgentScan

**MCP 暴露面扫描器** — 发现网络上未经认证的 Model Context Protocol 服务器，枚举其工具，并检测蜜罐。

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

## 功能特性

- **主动 CIDR/IP/域名扫描** — 无需 Shodan，无确认提示，直接扫描
- **多种输入格式** — IP、CIDR、IP 范围（`1.1.1.1-2.2.2.3`）、域名、`host:port`、URL（`https://host/path`）
- **精准 MCP 指纹识别** — 三层加权评分（≥0.65 确认为 MCP），排除 LSP 和通用 JSON-RPC 误报
- **SNI 感知 HTTPS** — 正确处理需要 TLS SNI（Server Name Indication）的反向代理服务器
- **URL 路径保留** — `https://host/custom-mcp` 优先探测 `/custom-mcp`
- **双传输协议支持** — Streamable HTTP（当前规范）和旧版 HTTP+SSE（2024-11-05，仍有 1,227+ 台服务器在用）
- **工具枚举** — 只读调用 `tools/list`，从不调用 `tools/call`
- **蜜罐检测 (Honeypot Detection)** — 通过 Session ID 一致性和协议版本验证识别诱饵服务器
- **JSON + 终端输出** — 机器可读报告，支持管道（`--format json 2>/dev/null | jq`）
- **`NO_COLOR` 支持** — 遵循 [no-color.org](https://no-color.org/) 标准

---

## 快速开始

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
go build -o agentscan .

# 扫描域名
./agentscan scan api.example.com

# 扫描子网
./agentscan scan 192.168.1.0/24

# 扫描 IP 范围
./agentscan scan 10.0.0.1-10.0.0.50

# 从目标文件扫描
./agentscan scan -f targets.txt

# 直接扫描指定 MCP URL
./agentscan scan https://api.example.com/mcp

# 将结果保存为 JSON
./agentscan scan 10.0.0.0/24 --format json -o results.json

# 使用 -t 指定多个目标
./agentscan scan -t 192.168.1.0/24 -t api.example.com
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

```
agentscan scan [OPTIONS] [TARGET...]

目标选项：
  -t, --target value     目标（IP、CIDR、IP 范围、域名、host:port、URL），可重复使用
  -f, --file value       目标文件（每行一个，支持 # 注释）

扫描选项：
  --ports value          逗号分隔的端口列表
                         （默认：80,443,8000,8080,8443,3000,3001,4000,5000,9000）
  --threads value, -T    最大并发 TCP 连接数（默认：500）
  --timeout value        TCP 连接超时毫秒（默认：500）
                         HTTP 超时 = timeout × 10，MCP 超时 = timeout × 20
  --exclude-honeypots    从结果中排除疑似蜜罐

输出选项：
  -o, --output value     JSON 输出文件路径
  --format value         terminal | json（默认：terminal）
  --verbose-raw          在 JSON 中包含原始 initialize 响应（每台服务器增加约 2 KB）
  --no-color, --Cn       禁用 ANSI 颜色（也可设置 NO_COLOR 环境变量）
```

### 目标格式

```
# 单个 IP
10.0.0.1

# CIDR（最大 /12，约 100 万 IP）
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
agentscan scan 192.168.1.0/24 --format json
agentscan scan --format json 192.168.1.0/24
agentscan scan -t 192.168.1.0/24 --format json -o out.json
```

---

## 最佳实践

AgentScan 是 **MCP 攻击面发现工具**，不是通用端口扫描器。根据目标规模选择合适的工作方式。

### 小范围（单个主机 / 小子网）

直接用 AgentScan，内置 TCP 扫描已经够用：

```bash
./agentscan scan 192.168.1.0/24
./agentscan scan api.example.com
```

### 大范围（互联网 / 大 CIDR）

AgentScan 与专用端口扫描器配合使用。让 masscan/nmap 承担大规模 TCP 扫描，再把开放端口喂给 AgentScan 做 MCP 识别：

```bash
# 第一步：masscan 快速 TCP 扫描，发现开放端口
masscan 10.0.0.0/8 -p 80,443,8000,8080,8443,3000,3001,4000,5000,9000 \
  --rate 100000 -oG open_ports.txt

# 第二步：转换 masscan 输出为 host:port 列表
grep "Host:" open_ports.txt | awk '{print $2":"$5}' | sed 's|/open||' > targets.txt

# 第三步：AgentScan 做 MCP 指纹识别、工具枚举、蜜罐检测
./agentscan scan -f targets.txt --format json -o results.json
```

> 这种分工是有意为之：masscan/nmap 为原始 TCP 吞吐量优化；AgentScan 为 MCP 协议层分析优化。两者互补，而非替代。

### 通过互联网测绘平台被动发现

用 Shodan/FOFA/ZoomEye 查询语句获取预过滤的候选列表，再用 AgentScan 验证：

```bash
# 从 Shodan/FOFA 导出 IP:port 列表，然后：
./agentscan scan -f shodan_results.txt --format json -o verified.json
```

### 已知目标的定向探测

当你已经知道某台主机运行 MCP（例如来自 Shodan 结果），可以直接跳过端口扫描：

```bash
# 直接指定 URL — 跳过端口扫描和 HTTP 筛选，直接进入 MCP 探测
./agentscan scan https://api.example.com/mcp
./agentscan scan https://api.example.com:8443/v1/mcp
```

### CI / 自动化流水线

```bash
# 退出码 0 = 扫描完成（不管有没有发现）
# 用 jq 解析结果
./agentscan scan 10.0.0.0/24 --format json 2>/dev/null \
  | jq '.results[] | select(.no_auth == true) | {ip, port, server_name, tool_count}'
```

---

## 输出

### 终端（默认）

```
[MCP] 203.0.113.42:443  /mcp  streamable_http  v=2025-06-18  no-auth
      server="Binance Square Publisher/1.27.2"  tools=1

[MCP] 203.0.113.10:3000  /sse  http_sse_legacy  v=2024-11-05  no-auth
      server="internal-tools/2.1"  tools=4
      [HONEYPOT] score=60  signals: invalid_version_accepted:9999-99-99, session_id_identical:abc123

=== AgentScan Summary ===
MCP servers found : 2
  Unauthenticated : 2
  Honeypots       : 1
```

进度和警告输出到 **stderr**；JSON 结果输出到 **stdout**，支持管道：

```bash
agentscan scan 10.0.0.0/24 --format json 2>/dev/null | jq '.results[].server_name'
```

### JSON

```json
{
  "version": "1.0",
  "summary": {
    "total": 1,
    "unauthenticated": 1,
    "honeypots": 0
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
  ▼  阶段 1：目标解析
     域名解析为 IP，保留 hostname 用于 SNI
     保留 URL 路径（如 /mcp）供优先探测
  │
  ▼  阶段 2：TCP 端口扫描（并发，默认 500ms 超时）
     端口：80 443 8000 8080 8443 3000 3001 4000 5000 9000
  │
  ▼  阶段 3：HTTP 筛选（并发 GET /，读取 Server/Content-Type 头）
  │
  ▼  阶段 4：MCP 指纹识别（SNI 感知 HTTPS，≥0.65 分确认为 MCP）
     探测端点顺序：用户路径 → /mcp → /sse → / → /messages → /api/mcp → /v1/mcp
     评分规则：
       protocolVersion 存在              +0.2
       MCP 特有 capabilities key         +0.3
       serverInfo.name 存在              +0.1
       （出现 LSP capabilities → 分数归零，排除）
  │
  ▼  阶段 5：深度分析（并行）
     5A：工具枚举（tools/list — 只读，从不调用 tools/call）
     5B：蜜罐检测（2 个信号）
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
"MCP-Protocol-Version"
"protocolVersion" "2025-11-25"
"protocolVersion" "2025-06-18"
"protocolVersion" "2024-11-05"
"serverInfo" "protocolVersion"
port:8000 "jsonrpc" "tools"
port:3000 "text/event-stream" "jsonrpc"
port:8080 "text/event-stream" "mcp"
"uvicorn" "mcp"
"fastmcp"
http.title:"MCP Server"
```

### FOFA

> **推荐用于国内目标** — 对 WAF 后方资产的覆盖显著优于 Shodan。

```
header="MCP-Protocol-Version"
header="MCP-Session-Id"
body="protocolVersion" && body="serverInfo" && body="capabilities"
body="tools/list" && body="jsonrpc"
header="text/event-stream" && body="jsonrpc" && body="mcp"
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

> ⚠️ Censys 仅索引 HTTP 响应体的前 **2 KB**，MCP `initialize` 响应通常超过此限制，正文搜索漏报率高，建议仅使用响应头搜索。

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
  models/        数据结构（MCPServer, ScanConfig, HoneypotResult）
  target/        输入解析（IP、CIDR、范围、域名、URL）
  scanner/
    port.go      TCP 端口扫描（goroutine + semaphore）
    http_filter  HTTP 候选筛选（并发，SNI 感知）
    mcp_probe    MCP 指纹识别（三层评分，双传输协议）
    enum.go      工具枚举（tools/list，只读）
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

- AgentScan 只调用 `tools/list`，从不调用 `tools/call`
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
