# AgentScan

**MCP exposure surface scanner** — discovers unauthenticated Model Context Protocol servers on the network, enumerates their tools, and detects honeypots.

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

## Features

- **Active CIDR/IP/domain scanning** — no Shodan dependency, no confirmation prompt
- **Multiple input formats** — IP, CIDR, IP range (`1.1.1.1-2.2.2.3`), domain, `host:port`, URL (`https://host/path`)
- **Accurate MCP fingerprinting** — 3-layer weighted scoring (≥0.65 = confirmed MCP), rejects LSP and generic JSON-RPC false positives
- **SNI-aware HTTPS** — correctly handles servers behind reverse proxies requiring TLS Server Name Indication
- **URL path preservation** — `https://host/custom-mcp` probes `/custom-mcp` first
- **Dual transport support** — Streamable HTTP (current spec) and legacy HTTP+SSE (2024-11-05, used by 1,227+ live servers)
- **Tool enumeration** — read-only `tools/list`, never calls `tools/call`
- **Honeypot detection** — identifies decoy servers via session ID consistency and protocol version validation
- **JSON + terminal output** — machine-readable reports, works with pipes (`--format json 2>/dev/null | jq`)
- **`NO_COLOR` support** — respects the [no-color.org](https://no-color.org/) standard

---

## Quick Start

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
go build -o agentscan .

# Scan a domain
./agentscan scan api.example.com

# Scan a subnet
./agentscan scan 192.168.1.0/24

# Scan an IP range
./agentscan scan 10.0.0.1-10.0.0.50

# Scan from a target file
./agentscan scan -f targets.txt

# Scan a specific MCP URL directly
./agentscan scan https://api.example.com/mcp

# Save results as JSON
./agentscan scan 10.0.0.0/24 --format json -o results.json

# Multiple targets with -t
./agentscan scan -t 192.168.1.0/24 -t api.example.com
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

```
agentscan scan [OPTIONS] [TARGET...]

Target options:
  -t, --target value     Target(s): IP, CIDR, IP range, domain, host:port, URL. Repeatable.
  -f, --file value       File with targets (one per line, # comments supported)

Scan options:
  --ports value          Comma-separated port list
                         (default: 80,443,8000,8080,8443,3000,3001,4000,5000,9000)
  --threads value, -T    Max concurrent TCP connections (default: 500)
  --timeout value        TCP connect timeout ms (default: 500)
                         HTTP timeout = timeout × 10, MCP timeout = timeout × 20
  --exclude-honeypots    Exclude suspected honeypots from results

Output options:
  -o, --output value     JSON output file path
  --format value         terminal | json  (default: terminal)
  --verbose-raw          Include raw initialize response in JSON (increases size ~2 KB/server)
  --no-color, --Cn       Disable ANSI colors (also: set NO_COLOR env var)
```

### Target formats

```
# Single IP
10.0.0.1

# CIDR (max /12 ~1M IPs)
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
agentscan scan 192.168.1.0/24 --format json
agentscan scan --format json 192.168.1.0/24
agentscan scan -t 192.168.1.0/24 --format json -o out.json
```

---

## Output

### Terminal (default)

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

Progress and warnings go to **stderr**; only JSON results go to **stdout**. Safe to pipe:

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

## How It Works

```
Input (IP / CIDR / IP range / domain / URL / file)
  │
  ▼  Stage 1: Target parsing
     Resolves domains to IPs, preserves hostname for SNI
     Preserves URL path (e.g. /mcp) for priority probing
  │
  ▼  Stage 2: TCP port scan   (concurrent, default 500ms timeout)
     Ports: 80 443 8000 8080 8443 3000 3001 4000 5000 9000
  │
  ▼  Stage 3: HTTP filter     (concurrent GET /, reads Server/Content-Type headers)
  │
  ▼  Stage 4: MCP fingerprint (SNI-aware HTTPS, ≥0.65 score = confirmed MCP)
     Endpoints tried: user path → /mcp → /sse → / → /messages → /api/mcp → /v1/mcp
     Score:  protocolVersion present          +0.2
             MCP-specific capabilities key    +0.3
             serverInfo.name present          +0.1
             (LSP capabilities → score = 0, rejected)
  │
  ▼  Stage 5: Deep analysis   (parallel)
     5A: Tool enumeration  (tools/list — read-only, never tools/call)
     5B: Honeypot detection (2 signals)
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

> ⚠️ Censys indexes only the first **2 KB** of HTTP response bodies — MCP `initialize` responses often exceed this, causing high miss rates. Use header-based searches only.

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
  models/        Data structures (MCPServer, ScanConfig, HoneypotResult)
  target/        Input parsing (IP, CIDR, range, domain, URL)
  scanner/
    port.go      TCP port scan (goroutine + semaphore)
    http_filter  HTTP candidate filtering (concurrent, SNI-aware)
    mcp_probe    MCP fingerprinting (3-layer scoring, dual transport)
    enum.go      Tool enumeration (tools/list, read-only)
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

- AgentScan only calls `tools/list` — it never invokes `tools/call`
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

AgentScan is provided for **authorized security testing and research only**.  
The authors are not responsible for any misuse or damage caused by this tool.
