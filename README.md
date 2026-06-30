# AgentScan

[English](README_en.md) | 中文

> 一条命令盘点 MCP、A2A Agent Card 和 LLM 开放接口暴露面。

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/7anX/AgentScan?style=social)](https://github.com/7anX/AgentScan/stargazers)
[![License](https://img.shields.io/github/license/7anX/AgentScan)](LICENSE)

传统端口扫描器只告诉你"这里有个 HTTP 服务"。AgentScan 继续往下走一层：判断这个服务是不是 MCP、是不是 A2A Agent、是不是开放的 LLM 接口，并输出可用工具、Agent 能力、模型列表和认证状态。

## 能扫什么

| 协议 | 识别内容 |
| --- | --- |
| MCP Server | Streamable HTTP、HTTP+SSE legacy、工具/资源/提示词列表、认证状态、蜜罐信号 |
| A2A Agent | Agent Card、skills、interfaces、无认证 JSON-RPC 可达性、私网地址泄露 |
| LLM 开放接口 | Ollama、vLLM、SGLang、TGI、llama.cpp、Xinference、LiteLLM、FastChat、LocalAI、LM Studio、LMDeploy |

## 快速开始

**Linux / macOS（从源码编译）**

```bash
git clone https://github.com/7anX/AgentScan
cd AgentScan
go build -o agentscan .

# 扫域名或 IP
./agentscan scan example.com

# 扫内网段
./agentscan scan 192.168.1.0/24

# 跳过端口扫描，直接验证已知 host:port
./agentscan scan -f targets.txt --skip-port-scan
```

**Linux 预编译二进制（无需 Go 环境）**

```bash
# amd64
curl -L https://github.com/7anX/AgentScan/releases/latest/download/agentscan_linux_amd64.tar.gz | tar xz
chmod +x agentscan && sudo mv agentscan /usr/local/bin/

# arm64（树莓派、ARM 云服务器）
curl -L https://github.com/7anX/AgentScan/releases/latest/download/agentscan_linux_arm64.tar.gz | tar xz
chmod +x agentscan && sudo mv agentscan /usr/local/bin/
```

**Windows**

```powershell
go build -o agentscan.exe .
.\agentscan.exe scan example.com
```

## 命令

```text
agentscan scan   # MCP + A2A + LLM 全协议扫描（最常用）
agentscan mcp    # 只扫 MCP
agentscan a2a    # 只扫 A2A Agent Card
agentscan llm    # 只扫 LLM 开放接口
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


## 组合用法

```bash
# masscan 发现端口，AgentScan 做 AI 协议识别
masscan 10.0.0.0/8 -p 80,443,8000,8080,11434 --rate 100000 -oL open_ports.txt
awk '/open/ {print $4 ":" $3}' open_ports.txt > targets.txt
agentscan scan -f targets.txt --skip-port-scan

# 测绘平台结果二次验证
agentscan scan -f fofa_export.txt --skip-port-scan --mcp-threads 200
```

## 博客

- [MCP 暴露面的安全问题](https://7anx.github.io/security-research/mcp-attack-surface/)
- [A2A 暴露面的安全问题](https://7anx.github.io/security-research/a2a-attack-surface/)
- [AgentScan 使用说明](https://7anx.github.io/agentscan/agentscan-use-cases/)
- [AgentScan 工作原理](https://7anx.github.io/agentscan/agentscan-architecture/)

## 赞助商

感谢以下安全社区对本项目的支持：

<table>
  <tr>
    <td align="center">
      <img src="docs/yunkunlab.jpg" alt="云鲲安全实验室" width="120"><br>
      <b>云鲲安全实验室</b>
    </td>
  </tr>
</table>

## 社区

本项目在 [LINUX DO](https://linux.do) 社区开源推广。

## 免责声明

本工具仅面向合法授权的企业安全建设行为。使用前请确保已获得授权，符合当地法律法规，不对非授权目标扫描。作者不承担任何非法使用产生的后果。
