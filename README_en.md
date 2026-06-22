# AgentScan

English | [中文](README.md)

> Discover exposed MCP servers, A2A Agent Cards, and open LLM APIs in one command.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![GitHub stars](https://img.shields.io/github/stars/7anX/AgentScan?style=social)](https://github.com/7anX/AgentScan/stargazers)
[![License](https://img.shields.io/github/license/7anX/AgentScan)](LICENSE)

Traditional port scanners only tell you "there's an HTTP service here." AgentScan goes one layer deeper: it determines whether a service is an MCP server, an A2A Agent, or an open LLM inference API — and reports available tools, agent capabilities, model lists, and authentication status.

## What It Scans

| Protocol | Identification |
| --- | --- |
| MCP Server | Streamable HTTP, HTTP+SSE legacy, tools/resources/prompts listing, auth status, honeypot signals |
| A2A Agent | Agent Card, skills, interfaces, unauthenticated JSON-RPC reachability, private address leaks |
| Open LLM APIs | Ollama, vLLM, SGLang, TGI, llama.cpp, Xinference, LiteLLM, FastChat, LocalAI, LM Studio, LMDeploy |

## Quick Start

**Linux / macOS (build from source)**

```bash
git clone https://github.com/7anX/AgentScan
cd AgentScan
go build -o agentscan .

# Scan a domain or IP
./agentscan scan example.com

# Scan an internal subnet
./agentscan scan 192.168.1.0/24

# Skip port scanning, verify known host:port directly
./agentscan scan -f targets.txt --skip-port-scan
```

**Linux pre-built binaries (no Go required)**

```bash
# amd64
curl -L https://github.com/7anX/AgentScan/releases/latest/download/agentscan_linux_amd64.tar.gz | tar xz
chmod +x agentscan && sudo mv agentscan /usr/local/bin/

# arm64 (Raspberry Pi, ARM cloud servers)
curl -L https://github.com/7anX/AgentScan/releases/latest/download/agentscan_linux_arm64.tar.gz | tar xz
chmod +x agentscan && sudo mv agentscan /usr/local/bin/
```

**Windows**

```powershell
go build -o agentscan.exe .
.\agentscan.exe scan example.com
```

## Commands

```text
agentscan scan   # Full protocol scan: MCP + A2A + LLM (most common)
agentscan mcp    # MCP only
agentscan a2a    # A2A Agent Card only
agentscan llm    # Open LLM APIs only
```

Common flags:

```text
-f, --file FILE          Read targets from file (one per line)
-T, --threads N          TCP scan concurrency, default 500
--timeout MS             TCP timeout, default 2000ms
--skip-port-scan         Treat input as already-open host:port
--proxy URL              socks5/socks4/https/http proxy
-o, --output FILE        Write JSON; A2A/LLM auto-append _a2a.json / _llm.json
-v, --verbose            Show probe details
```

## Combo Usage

```bash
# Use masscan for port discovery, then AgentScan for AI protocol identification
masscan 10.0.0.0/8 -p 80,443,8000,8080,11434 --rate 100000 -oL open_ports.txt
awk '/open/ {print $4 ":" $3}' open_ports.txt > targets.txt
agentscan scan -f targets.txt --skip-port-scan

# Re-validate results from asset mapping platforms
agentscan scan -f fofa_export.txt --skip-port-scan --mcp-threads 200
```

## Blog

- [MCP Attack Surface](https://7anx.github.io/posts/mcp-attack-surface/) *(Chinese)*
- [A2A Attack Surface](https://7anx.github.io/posts/a2a-attack-surface/) *(Chinese)*
- [AgentScan Use Cases](https://7anx.github.io/posts/agentscan-use-cases/) *(Chinese)*
- [AgentScan Architecture](https://7anx.github.io/posts/agentscan-architecture/) *(Chinese)*

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Community

This project is open-sourced and promoted in the [LINUX DO](https://linux.do) community.

## Disclaimer

This tool is intended solely for legally authorized enterprise security assessments. Ensure you have proper authorization before use and comply with local laws and regulations. Do not scan unauthorized targets. The authors assume no liability for any illegal use.

## Sponsors

Thanks to the following security communities for promoting this project:

<table>
  <tr>
    <td align="center">
      <img src="docs/yunkunlab.jpg" alt="YunKun Security Lab" width="120"><br>
      <b>云鲲安全实验室</b>
    </td>
  </tr>
</table>
