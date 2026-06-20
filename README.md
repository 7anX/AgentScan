# AgentScan

> 一条命令盘点 MCP、A2A Agent Card 和 LLM 推理 API 暴露面。

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/7anX/AgentScan?style=social)](https://github.com/7anX/AgentScan/stargazers)

AgentScan 是为 AI 时代写的暴露面扫描器。传统端口扫描器只会告诉你“这里有个 HTTP 服务”，AgentScan 继续往下走一层：它会判断这个服务是不是 MCP、是不是 A2A Agent、是不是开放的 LLM 推理 API，并把可用工具、Agent 能力、模型列表、认证状态和证据整理成可读报告。

如果你的网络里已经开始出现各种 AI Agent、MCP Server、Ollama、vLLM、SGLang、LiteLLM、LM Studio，AgentScan 就是用来回答这个问题的：

**这些 AI 能力到底有没有被不该访问的人访问到？**

## 它能扫什么

| 面向对象 | AgentScan 会看什么 |
| --- | --- |
| MCP Server | Streamable HTTP、HTTP+SSE legacy、工具列表、资源、提示词、认证状态、蜜罐信号 |
| A2A Agent | Agent Card、skills、interfaces、公开 JSON-RPC、私网地址泄露、扩展卡暴露 |
| LLM Inference API | Ollama、vLLM、SGLang、TGI、llama.cpp、Xinference、LiteLLM、FastChat、LocalAI、LM Studio、LMDeploy 等 |

## 为什么值得用

- **AI 原生暴露面**：不是通用端口扫描器套壳，而是直接面向 MCP、A2A、LLM 推理 API 的协议识别。
- **一条流水线覆盖三类风险**：端口扫描、HTTP 过滤、协议指纹、能力枚举和报告生成一次跑完。
- **不依赖 Shodan/FOFA**：可以扫内网、实验环境、资产平台导出的目标，也可以接 masscan 结果。
- **只读探测**：MCP 不调用 `tools/call`，A2A 不创建任务，LLM 不触发推理，不拉模型。
- **证据链友好**：JSON 适合进自动化，HTML/TXT 适合给团队、老板或甲方看。
- **可扩展**：端口、路径、HTTP hints 可以换字典，LLM 指纹可以用 YAML 模板追加。

## 快速开始

```bash
git clone https://github.com/7anX/AgentScan
cd AgentScan
go build -o agentscan .

# 扫一个域名或 IP
./agentscan scan example.com

# 扫一段内网
./agentscan scan 192.168.1.0/24

# 验证已知开放的 host:port 列表
./agentscan scan -f targets.txt --skip-port-scan -o findings.json
```

Windows:

```powershell
go build -o agentscan.exe .
.\agentscan.exe scan example.com
```

完整参数、输出字段和调优建议见博客：

- [AgentScan 使用手册：从内网盘点到互联网测绘](https://7anx.github.io/posts/agentscan-use-cases/)
- [AgentScan 工作原理：MCP、A2A 与 LLM 指纹识别](https://7anx.github.io/posts/agentscan-architecture/)

## 典型使用场景

### 1. 内网 AI 资产盘点

很多团队已经在内网跑了 Ollama、LM Studio、vLLM、Langflow、FastMCP、各种 demo Agent，但这些服务经常不是通过正式资产流程上线的。最后安全团队看到的不是“AI 基础设施”，而是一堆没人登记的 `8000`、`8080`、`11434`。

AgentScan 适合直接扫办公网、研发网、测试网：

```bash
agentscan scan 10.10.0.0/16 --timeout 300 --threads 2000 -o intranet-ai.json
```

输出里你能直接看到：

- 哪些服务是 MCP / A2A / LLM API。
- 哪些没有认证。
- LLM API 暴露了哪些模型。
- MCP 暴露了哪些工具、资源和提示词。
- Agent Card 有没有把私网接口、管理能力或高危 skill 直接写出来。

这比“扫出来一个 8000 端口，再人工点开看”省很多时间。

### 2. 测绘平台结果二次验证

FOFA、Quake、Shodan、ZoomEye 很适合找候选目标，但测绘结果常常只是“像 MCP / 像 LLM”。真正要做研判，还得做协议层确认。

把平台导出的 `host:port` 喂给 AgentScan：

```bash
agentscan scan -f exported.txt --skip-port-scan --mcp-threads 200 -o verified.json
```

AgentScan 会跳过 TCP 端口扫描，直接做 HTTP 与协议探测，适合批量验证：

- 候选目标到底是不是 MCP。
- 是公开可访问，还是需要认证。
- 返回的是正常服务、误报，还是疑似蜜罐。
- 是否同时暴露 A2A 或 LLM API。

### 3. 红队和安全研究

AI Agent 暴露面的麻烦在于：风险不只来自“接口开着”，还来自接口背后的能力。一个 MCP Server 如果公开了 `run_command`、`query_database`、`deploy_k8s` 这类工具，风险级别和普通 HTTP 服务不是一回事。

AgentScan 会把协议识别和能力枚举放在一起，帮助快速回答：

- 这个服务是不是 AI Agent 相关协议。
- 它能调用什么工具。
- 它能访问什么资源。
- 它是不是只是公开卡片，还是 JSON-RPC 也无认证可达。
- 它是不是公开了本地模型推理能力。

报告可以直接作为后续人工验证和风险说明的入口。

### 4. 蓝队持续监控

AgentScan 的 JSON 输出可以直接接 CI、定时任务、SIEM 或资产系统。你可以每天扫一次关键网段，发现新的 no-auth MCP、公开 LLM API 或异常 Agent Card 就报警。

```bash
agentscan scan -f critical-ranges.txt --format json -o daily.json
```

它更像一个“AI 暴露面巡检器”：不是替代 Nmap，而是补上 Nmap 不理解 AI 协议的那一层。

### 5. masscan + AgentScan 跑大范围

大范围 TCP 吞吐交给 masscan，协议确认交给 AgentScan：

```bash
masscan 10.0.0.0/8 -p 80,443,8000,8080,11434 --rate 100000 -oL open_ports.txt
awk '/open/ {print $4 ":" $3}' open_ports.txt > targets.txt
agentscan scan -f targets.txt --skip-port-scan -o results.json
```

这套组合适合互联网测绘、企业大网段盘点和研究数据集清洗。

## 报告长什么样

AgentScan 默认会生成终端输出，同时写出 HTML/TXT 报告；指定 `-o` 后还会写 JSON。

统一扫描会生成：

```text
results.json        # MCP 结果
results_a2a.json    # A2A 结果
results_llm.json    # LLM 结果
agentscan-report-*/report.html
agentscan-report-*/report_en.html
agentscan-report-*/summary.txt
```

HTML 报告按 MCP / A2A / LLM 分 tab 展示，适合快速浏览和交付；JSON 保留证据字段，适合自动化处理。

## 什么时候不该用

AgentScan 不是漏洞利用工具，也不是为了帮你“打”别人的 AI 服务。它适合授权范围内的资产识别、暴露面盘点、研究验证和持续巡检。

未授权扫描第三方系统可能违反法律法规。请只扫描你拥有或被授权测试的目标。

## Star 一下？

AI Agent 生态正在快速把“接口”变成“能力”。以前暴露一个端口，最多是一个 Web 服务；现在暴露一个 Agent，后面可能连着数据库、Kubernetes、文件系统、云账号和本地模型。

AgentScan 想做的事情很直接：让这些新暴露面更容易被发现、更容易被解释、更容易被修。

如果这个方向对你有用，点个 Star，后续会继续补：

- 更多 Agent 协议。
- 更多 LLM / AI Gateway 指纹。
- 更好的风险分级。
- 更适合企业巡检的输出格式。
- 更完整的博客案例和测绘数据分析。

## 免责声明

AgentScan 仅供授权安全测试、资产自查和研究使用。作者不对误用本工具造成的任何损失或后果承担责任。
