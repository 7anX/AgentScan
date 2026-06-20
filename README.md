# AgentScan

> 一条命令盘点 MCP、A2A Agent Card 和 LLM 推理 API 暴露面。

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/7anX/AgentScan?style=social)](https://github.com/7anX/AgentScan/stargazers)
[![License](https://img.shields.io/github/license/7anX/AgentScan)](LICENSE)

传统端口扫描器只告诉你"这里有个 HTTP 服务"。AgentScan 继续往下走一层：判断这个服务是不是 MCP、是不是 A2A Agent、是不是开放的 LLM 推理 API，并输出可用工具、Agent 能力、模型列表和认证状态。

## 能扫什么

| 协议 | 识别内容 |
| --- | --- |
| MCP Server | Streamable HTTP、HTTP+SSE legacy、工具/资源/提示词列表、认证状态、蜜罐信号 |
| A2A Agent | Agent Card、skills、interfaces、无认证 JSON-RPC 可达性、私网地址泄露 |
| LLM 推理 API | Ollama、vLLM、SGLang、TGI、llama.cpp、Xinference、LiteLLM、FastChat、LocalAI、LM Studio、LMDeploy |

## 快速开始

```bash
git clone https://github.com/7anX/AgentScan
cd AgentScan
go build -o agentscan .

# 扫域名或 IP
./agentscan scan example.com

# 扫内网段
./agentscan scan 192.168.1.0/24

# 跳过端口扫描，直接验证已知 host:port
./agentscan scan -f targets.txt --skip-port-scan -o findings.json
```

Windows：

```powershell
go build -o agentscan.exe .
.\agentscan.exe scan example.com
```

## 命令

```text
agentscan scan   # MCP + A2A + LLM 全协议扫描（最常用）
agentscan mcp    # 只扫 MCP
agentscan a2a    # 只扫 A2A Agent Card
agentscan llm    # 只扫 LLM 推理 API
```

常用参数：

```text
-f, --file FILE          从文件读取目标（每行一个）
-T, --threads N          TCP 扫描并发，默认 500
--timeout MS             TCP 超时，默认 2000ms
--skip-port-scan         输入视为已开放的 host:port
--proxy URL              socks5/socks4/https/http 代理
-o, --output FILE        写 JSON；A2A/LLM 自动写 _a2a.json / _llm.json
-v, --verbose            显示探测详情
```

## 输出

```text
results.json           # MCP
results_a2a.json       # A2A
results_llm.json       # LLM
agentscan-report-*/    # HTML + TXT 报告（中英文）
```

## 组合用法

```bash
# masscan 发现端口，AgentScan 做 AI 协议识别
masscan 10.0.0.0/8 -p 80,443,8000,8080,11434 --rate 100000 -oL open_ports.txt
awk '/open/ {print $4 ":" $3}' open_ports.txt > targets.txt
agentscan scan -f targets.txt --skip-port-scan -o results.json

# 测绘平台结果二次验证
agentscan scan -f fofa_export.txt --skip-port-scan --mcp-threads 200 -o verified.json
```

## 博客

- [MCP 暴露面的安全问题](https://7anx.github.io/posts/mcp-attack-surface/)
- [A2A 暴露面的安全问题](https://7anx.github.io/posts/a2a-attack-surface/)
- [AgentScan 使用说明](https://7anx.github.io/posts/agentscan-use-cases/)
- [AgentScan 工作原理](https://7anx.github.io/posts/agentscan-architecture/)

## 注意

只读探测：MCP 不调用 `tools/call`，A2A 不创建任务，LLM 不触发推理，不拉模型。

请只扫描你拥有或被授权测试的目标。未授权扫描第三方系统可能违反法律法规。
