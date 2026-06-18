English | [中文](README_CN.md)

# AgentScan

**AI agent protocol exposure scanner** — discovers unauthenticated Model Context Protocol servers on the network, enumerates their tools, resources, and prompts, and detects honeypots.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Background

The [Model Context Protocol (MCP)](https://modelcontextprotocol.io) connects AI agents to external tools and data sources. Since authentication is **optional** in the spec, many deployed servers are fully open.

**Scale of the problem (2025–2026):**

| Source | Date | Exposed servers found |
|--------|------|-----------------------|
| Trend Micro | 2025-07 | 492 |
| Bitsight TRACE | 2025-12 | ~1,000 |
| Trend Micro (update) | 2026-04 | 1,467 |
| arXiv 2605.22333 | 2026-05 | **7,973** (40.55% unauthenticated) |
| GuidePoint Security | 2026-06 | **2,305** (of 62,000 probed) |

Real-world impact includes unauthenticated access to Kubernetes clusters, CRM databases, and AWS credentials embedded in tool descriptions.

---

## Why "AgentScan"?

MCP started it, but the AI agent ecosystem is bigger than one protocol. The name reflects where this tool is headed.

AI agents don't communicate through a single standard. The current landscape has several overlapping protocols, each with its own discovery endpoints and exposure characteristics:

| Protocol | Owner | Role | Discovery endpoint |
|----------|-------|------|--------------------|
| **MCP** | Anthropic | Agent ↔ Tool | JSON-RPC `initialize` handshake |
| **A2A** | Google / Linux Foundation | Agent ↔ Agent | `/.well-known/agent.json` |
| **ACP** | IBM / BeeAI | Agent ↔ Agent (REST) | `/.well-known/agent.json` |
| **ChatGPT Plugin** | OpenAI | LLM ↔ External service | `/.well-known/ai-plugin.json` |

All of these share the same core problem: authentication is optional or absent, and the discovery endpoints are publicly reachable by design. "AgentScan" covers the whole surface.

### Protocol roadmap

- [x] MCP (Streamable HTTP + legacy HTTP+SSE)
- [ ] A2A — `/.well-known/agent.json`, `/.well-known/agent-card.json`, `A2A-Version` header
- [ ] ACP — `/.well-known/agent.json` (field-distinguished from A2A via `agentId` / `runs`)
- [ ] ChatGPT Plugin — `/.well-known/ai-plugin.json` (large existing install base, frequent `"auth": {"type": "none"}`)

---

## Features

- **Active CIDR/IP/domain scanning** — no Shodan dependency, no confirmation prompt
- **Multiple input formats** — IP, CIDR, IP range (`1.1.1.1-2.2.2.3`), domain, `host:port`, URL (`https://host/path`)
- **Accurate MCP fingerprinting** — 3-layer weighted scoring (≥0.65 = confirmed MCP), rejects LSP and generic JSON-RPC false positives
- **SNI-aware HTTPS** — correctly handles servers behind reverse proxies requiring TLS Server Name Indication
- **URL path preservation** — `https://host/custom-mcp` probes `/custom-mcp` first
- **Dual transport support** — Streamable HTTP (current spec) and legacy HTTP+SSE (2024-11-05, used by 1,227+ live servers)
- **Full exposure enumeration** — tools, resources, resource templates, and prompts (all read-only; never calls `tools/call`)
- **Honeypot detection** — identifies decoy servers via session ID consistency and protocol version validation
- **JSON + terminal output** — machine-readable reports, works with pipes (`--format json 2>/dev/null | jq`)
- **`NO_COLOR` support** — respects the [no-color.org](https://no-color.org/) standard

---

## Quick Start

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
go build -o agentscan .

# Scan all supported protocols on a domain
./agentscan scan api.example.com

# Scan only MCP
./agentscan mcp api.example.com

# Scan a subnet for MCP servers
./agentscan mcp 192.168.1.0/24

# Scan an IP range
./agentscan mcp 10.0.0.1-10.0.0.50

# Scan from a target file
./agentscan mcp -f targets.txt

# Scan a specific MCP URL directly
./agentscan mcp https://api.example.com/mcp

# Save results as JSON
./agentscan mcp 10.0.0.0/24 --format json -o results.json

# Multiple targets with -t
./agentscan mcp -t 192.168.1.0/24 -t api.example.com
```

> **No confirmation prompt.** AgentScan starts immediately. You are responsible for scanning only systems you are authorized to test.

---

## Build

```bash
# Native binary (current OS/arch)
powershell -ExecutionPolicy Bypass -File build.ps1   # Windows
./build.sh                                            # Linux/macOS

# Cross-compile
./build.sh linux amd64
./build.sh darwin arm64
powershell -ExecutionPolicy Bypass -File build.ps1 -OS linux -Arch amd64
```

Output: `dist/agentscan` (or `dist/agentscan.exe` on Windows).

---

## Usage

### Command structure

```
agentscan <command> [OPTIONS] [TARGET...]

Commands:
  mcp     Scan for exposed MCP (Model Context Protocol) servers
  scan    Scan for all supported protocols (runs all protocol scanners)
```

Each protocol command has its own flags tuned to that protocol's characteristics. Common flags (target input, output format, TCP scan options) are shared across all commands.

---

### `agentscan mcp` — MCP scanner

```
agentscan mcp [OPTIONS] [TARGET...]

Target options:
  -t, --target value     Target(s): IP, CIDR, IP range, domain, host:port, URL. Repeatable.
  -f, --file value       File with targets (one per line, # comments supported)

Scan options:
  --ports value          Comma-separated port list
                         (default: 8000,8001,443,3000,80,8080,3001,11003,7860,3030,8443,5000,8888,8787,5001,4000,9000)
  --threads value, -T    Max concurrent TCP connections (default: 500)
  --mcp-threads value    Max concurrent MCP probe connections (default: 50)
  --timeout value        TCP connect timeout ms (default: 500)
                         HTTP timeout = timeout × 10, MCP timeout = timeout × 20
  --skip-port-scan       Skip TCP port scan; treat all inputs as already-open IP:Port
  --exclude-honeypots    Exclude suspected honeypots from results

Output options:
  -o, --output value     JSON output file path
  --format value         terminal | json  (default: terminal)
  --verbose, -v          Per-stage progress logging: open ports, probe targets, response times
  --verbose-raw          Include raw initialize response in JSON (increases size ~2 KB/server)
  --no-color, --Cn       Disable ANSI colors (also: set NO_COLOR env var)
```

---

### `agentscan scan` — all protocols

```
agentscan scan [OPTIONS] [TARGET...]
```

Runs all protocol scanners in sequence against the same target set. Accepts the union of all protocol-specific flags. Output is tagged by protocol (`[MCP]`, `[A2A]`, etc.).

> Currently equivalent to `mcp` — additional protocols will be added as they are implemented.

### Default ports

Ports are selected based on evidence from real-world scanning data:

| Tier | Ports | Source |
|------|-------|--------|
| Tier 1 — real-world top | `8000, 8001, 443, 3000, 80, 8080, 3001` | Quake global top + FOFA `header="MCP-Protocol-Version"` |
| Tier 2 — framework defaults | `11003, 7860, 3030, 8443, 5000` | Quake China top (11003 prominent); Gradio (7860) |
| Tier 3 — low frequency | `8888, 8787, 5001, 4000, 9000` | Long tail observed in corpus |

### Target formats

```
# Single IP
10.0.0.1

# CIDR
10.0.0.0/24

# IP range
10.0.0.1-10.0.0.50
192.168.1.1-255        # short form: last octet only

# Domain
api.example.com

# Domain with specific port
api.example.com:8080

# URL — path is preserved and tried first
https://api.example.com/mcp
http://internal-host:8000/api/mcp

# File (-f targets.txt)
10.0.0.1
10.0.0.2:8000
192.168.1.0/24
# this is a comment
api.example.com
```

### Flag placement

Flags can appear **before or after** positional targets:

```bash
# All equivalent:
agentscan mcp 192.168.1.0/24 --format json
agentscan mcp --format json 192.168.1.0/24
agentscan mcp -t 192.168.1.0/24 --format json -o out.json
```

---

## Best Practices

AgentScan is an **AI agent protocol exposure scanner**, not a general-purpose port scanner. The right workflow depends on your target scope.

### Scenario 1: Mapping platform export (most common)

You've exported an IP:port list from Quake, FOFA, or Shodan. The ports are already confirmed open — re-running a TCP scan wastes time and connections. Use `--skip-port-scan` to jump straight to MCP probing.

```bash
# Export from Quake/FOFA as IP:port list, then verify with AgentScan
agentscan mcp -f quake_results.txt --skip-port-scan --mcp-threads 200 --format json -o verified.json
```

`--skip-port-scan` skips Stage 1 entirely and treats every line in the file as an already-open endpoint. This is roughly 3x faster for pre-filtered inputs because it cuts out TCP connection overhead for the scan phase.

### Scenario 2: masscan + AgentScan pipeline (internet-scale)

For large CIDRs, let masscan handle raw TCP throughput and feed the open ports to AgentScan for MCP-layer analysis. The two tools complement each other: masscan is optimized for packets-per-second; AgentScan is optimized for protocol correctness.

```bash
# Step 1: masscan for TCP — finds open ports at line rate
masscan 1.0.0.0/8 -p 8000,8001,443,3000,80,8080,3001,11003 --rate 100000 -oL open_ports.txt

# Step 2: convert masscan -oL output to host:port list
grep "open" open_ports.txt | awk '{print $4":"$3}' > targets.txt

# Step 3: AgentScan handles MCP fingerprinting, enumeration, honeypot detection
agentscan mcp -f targets.txt --skip-port-scan --mcp-threads 200 --timeout 3000 --format json -o results.json
```

### Scenario 3: Internal network segment scan

Low-latency internal networks tolerate much tighter timeouts and higher concurrency than the internet. Shrink `--timeout` to 200 ms and push `--threads` up to saturate the local link.

```bash
# Single subnet
agentscan mcp 192.168.1.0/24 --timeout 200 --threads 2000 --mcp-threads 100

# Multiple segments
agentscan mcp -t 10.0.0.0/8 -t 172.16.0.0/12 --timeout 200 --threads 2000 --mcp-threads 200 --format json -o intranet.json
```

> **Note:** a `/8` is 16M IPs × 17 default ports = ~272M TCP probes. Use `--ports` to limit scope to the two or three ports you actually expect to see on your network.

### Scenario 4: Single host or known URL (targeted research)

When a mapping platform result gives you a specific URL, skip all scanning stages and go directly to MCP probing. AgentScan preserves the URL path and uses it as the first probe target.

```bash
# Direct URL — Stage 1 and 2 are skipped automatically
agentscan mcp https://api.example.com/mcp

# Multiple known hosts, verbose output
agentscan mcp -t host:8000 -t host:3000 --skip-port-scan --verbose
```

### Scenario 5: CI / automated pipeline

JSON output goes to stdout; all progress messages go to stderr. That makes it safe to pipe through `jq` without filtering noise.

```bash
agentscan mcp 10.0.0.0/24 --format json -o results.json 2>/dev/null

# Find unauthenticated servers and print IP, port, and tool count
cat results.json | jq '.results[] | select(.no_auth == true) | {ip, port, tool_count}'
```

Exit code is always `0` on scan completion regardless of findings. Non-zero codes indicate a fatal error (bad flag, unresolvable target, etc.).

---

## Output

### Terminal (default)

```
[MCP] 1.2.3.4:8000  /mcp  streamable_http  v=2025-06-18  no-auth
      server="my-mcp/1.0"  tools=5  resources=2  res_templates=1  prompts=3

[MCP] 203.0.113.10:3000  /sse  http_sse_legacy  v=2024-11-05  no-auth
      server="internal-tools/2.1"  tools=4  resources=0  res_templates=0  prompts=0
      [HONEYPOT] score=60  signals: invalid_version_accepted:9999-99-99, session_id_identical:abc123

=== AgentScan Summary ===
Protocol  Servers  Unauth  Honeypots
MCP       2        2       1
─────────────────────────────────────
Total     2        2       1
  Auth-required   : 0
  Tools exposed   : 9
  Resources       : 2
  Res templates   : 0
  Prompts         : 3
```

Progress and warnings go to **stderr**; only JSON results go to **stdout**. Safe to pipe:

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

## How It Works

```
Input (IP / CIDR / IP range / domain / URL / file)
  │
  ▼  Target parsing
     Resolves domains to IPs, preserves hostname for SNI
     Preserves URL path (e.g. /mcp) for priority probing
  │
  ▼  Stage 1: TCP port scan   [skippable with --skip-port-scan]
     Ports (17): 8000 8001 443 3000 80 8080 3001 11003 7860
                 3030 8443 5000 8888 8787 5001 4000 9000
     Concurrent goroutines, default 500 ms connect timeout
  │
  ▼  Stage 2: HTTP filter
     Concurrent GET /, reads Server and Content-Type headers
     Drops non-HTTP responses early to reduce MCP probe load
  │
  ▼  Stage 3: MCP probe       (dual transport, --mcp-threads concurrency)
     Tries 25 endpoint paths: /mcp, /sse, /messages/, /gradio_api/mcp,
       /api/v1/mcp/sse, /.well-known/mcp/server-card.json, ...
     SSE paths: /sse, /mcp/sse, /mcp-server/sse, /sse/,
                /api/v1/mcp/sse, /gradio_api/mcp/
     Sends initialize, then notifications/initialized before any requests
     Fingerprint scoring:
       protocolVersion present          +0.2
       MCP-specific capabilities key    +0.3
       serverInfo.name present          +0.1
       LSP capabilities detected    → score = 0, rejected
     ≥ 0.65 = confirmed MCP
  │
  ▼  Stage 4: Exposure enumeration  (parallel, read-only)
     tools/list            → MCPTool    (name, description, inputSchema)
     resources/list        → MCPResource (uri, name, description, mimeType)
     resources/templates/list → MCPResourceTemplate (uriTemplate, name, description)
     prompts/list          → MCPPrompt  (name, description)
  │
  ▼  Stage 5: Honeypot detection (2 signals)
  │
  ▼  Output: terminal (stderr for progress) / JSON (stdout)
```

---

## Honeypot Detection

AgentScan detects decoy servers using two signals derived from Bitsight's analysis of 1,100+ honeypots:

| Signal | Score | Description |
|--------|-------|-------------|
| `invalid_version_accepted` | +20 | Server accepts `protocolVersion: "9999-99-99"` without error (spec requires rejection or `-32602`) |
| `session_id_identical` | +40 | Two separate `initialize` calls return the same `MCP-Session-Id` (spec requires globally unique IDs) |

Score ≥ 40 → `suspected_honeypot: true` (shown in output but not filtered by default; use `--exclude-honeypots` to exclude).

---

## Internet Mapping (Shodan / FOFA / ZoomEye)

The following queries locate publicly exposed MCP servers for **research purposes only**. Do not scan systems without authorization.

### Shodan

```
# Highest precision — MCP-specific HTTP response header
"MCP-Protocol-Version"

# Protocol version string in response body
"protocolVersion" "2025-11-25"
"protocolVersion" "2025-06-18"
"protocolVersion" "2024-11-05"

# serverInfo field (unique to MCP initialize response)
"serverInfo" "protocolVersion"

# Port + protocol combinations
port:8000 "jsonrpc" "tools"
port:3000 "text/event-stream" "jsonrpc"
port:8080 "text/event-stream" "mcp"

# Framework fingerprints
"uvicorn" "mcp"
"fastmcp"
http.title:"MCP Server"
```

### FOFA

> **Recommended for Chinese domestic targets** — significantly better coverage than Shodan behind WAFs.

```
# MCP-specific response headers (most precise)
header="MCP-Protocol-Version"
header="MCP-Session-Id"

# Body fingerprints
body="protocolVersion" && body="serverInfo" && body="capabilities"
body="tools/list" && body="jsonrpc"

# SSE transport
header="text/event-stream" && body="jsonrpc" && body="mcp"

# Framework fingerprints
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

> Censys indexes only the first **2 KB** of HTTP response bodies — MCP `initialize` responses often exceed this, causing high miss rates. Use header-based searches only.

```
services.http.response.headers: (key="Content-Type" and value="text/event-stream")
services.http.response.body: "serverInfo"
```

**Platform summary:**

| Platform | Best for | Notes |
|----------|----------|-------|
| **Shodan** | International targets | Industry standard; widest MCP community adoption |
| **FOFA** | Chinese domestic targets | Dominant coverage; better WAF bypass |
| ZoomEye | Supplementary | Good body search support |
| Censys | Header-only searches | 2 KB body limit causes body-search misses |

---

## Architecture

```
internal/
  sseutil/       Shared SSE parsing (ParseFirstMessage, ParseEndpointEvent)
  version/       Build-time version injection via -ldflags

pkg/
  models/        Data structures (MCPServer, MCPTool, MCPResource,
                   MCPResourceTemplate, MCPPrompt, ScanConfig, HoneypotResult)
  target/        Input parsing (IP, CIDR, range, domain, URL)
  scanner/
    port.go      TCP port scan (goroutine + semaphore)
    http_filter  HTTP candidate filtering (concurrent, SNI-aware)
    mcp_probe    MCP fingerprinting (3-layer scoring, dual transport,
                   25-path dictionary, notifications/initialized handshake)
    enum.go      Exposure enumeration: tools/list, resources/list,
                   resources/templates/list, prompts/list
    pipeline.go  Five-stage orchestration + RunScan entry point
  analysis/
    honeypot.go  Honeypot detection (2 signals)
  output/
    terminal.go  ANSI terminal output (NO_COLOR aware)
    json.go      Structured JSON report
```

---

## Legal & Ethics

> **This tool is for authorized security testing and research only.**  
> Scanning systems without permission may violate computer fraud and abuse laws in your jurisdiction.

- AgentScan only calls `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list` — it never invokes `tools/call` or writes anything to a server
- After finding exposed servers, follow responsible disclosure: notify the owner, allow 90 days to remediate before public disclosure
- The tool starts scanning immediately — no confirmation prompt. You are responsible for scanning only authorized targets.

---

## Related Research

| Source | Key finding |
|--------|-------------|
| [arXiv:2605.22333](https://arxiv.org/abs/2605.22333) (2026-05) | 7,973 live servers; 40.55% unauthenticated; used FOFA+Shodan to discover them |
| [arXiv:2510.16558](https://arxiv.org/abs/2510.16558) (DSN 2026) | Two-stage attack surface model; 833 vulnerable in 67,057 scanned |
| [arXiv:2601.17549](https://arxiv.org/abs/2601.17549) | Protocol version downgrade vulnerabilities; +23–41% attack success rate |
| [Bitsight TRACE](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities) (2025-12) | ~1,000 exposed; 1,100+ honeypots with fixed session IDs |
| [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud) (2026-04) | 1,467 exposed; CVSS 9.8 vulns in AWS/Azure MCP servers |
| [GuidePoint Security](https://www.guidepointsecurity.com/blog/mcp-deployment-security-ai-ai-ai/) (2026-06) | 2,305 exposed of 62,000 probed; finance/medical/ERP systems |

---

## License

MIT — see [LICENSE](LICENSE)

---

## Disclaimer

AgentScan is provided for **authorized security testing and research only.**  
The authors are not responsible for any misuse or damage caused by this tool.
