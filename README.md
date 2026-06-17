# AgentScan

**MCP exposure surface scanner** — discovers unauthenticated Model Context Protocol servers on the network, enumerates their tools, and assesses risk.

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

- **Active CIDR/IP/domain scanning** — no Shodan dependency
- **Accurate MCP fingerprinting** — 3-layer weighted scoring (≥0.65 = confirmed MCP), rejects LSP and generic JSON-RPC false positives
- **Dual transport support** — Streamable HTTP (current spec) and legacy HTTP+SSE (2024-11-05)
- **Tool enumeration** — reads-only `tools/list`, never calls `tools/call`
- **Risk assessment** — CRITICAL / HIGH / MEDIUM / LOW / INFO with MITRE ATT&CK mapping
- **Honeypot detection** — identifies decoy servers (fixed session ID, accepts invalid protocol versions)
- **JSON + terminal output** — machine-readable reports for CI/CD pipelines

---

## Quick Start

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
go build -o agentscan .

# Scan a subnet
./agentscan scan 192.168.1.0/24 --agree-tos

# Scan from a target file
./agentscan scan -f targets.txt --agree-tos

# Save results as JSON
./agentscan scan 10.0.0.0/8 --format json -o results.json --agree-tos

# Show only HIGH and above
./agentscan scan api.example.com --min-risk high --agree-tos
```

---

## Usage

```
agentscan scan [OPTIONS] [TARGET...]

Options:
  -f, --file string           Target file (one IP/CIDR/domain per line, # comments OK)
  --ports string              Port list (default: 80,443,8000,8080,8443,3000,3001,4000,5000,9000)
  --concurrency int           Max concurrent TCP connections (default: 500)
  --timeout-connect int       TCP connect timeout ms (default: 500)
  --timeout-http int          HTTP timeout ms (default: 5000)
  --timeout-mcp int           MCP probe timeout ms (default: 10000)
  --exclude-honeypots         Filter out suspected honeypots
  -o, --output string         JSON output file path
  --format string             terminal | json  (default: terminal)
  --min-risk string           critical | high | medium | low | info  (default: info)
  --no-color                  Disable ANSI colors
  --agree-tos                 Skip legal confirmation (for CI/CD)
```

### Target formats

```
# Single IP
10.0.0.1

# CIDR
10.0.0.0/24

# Domain
api.example.com

# Domain with specific port
api.example.com:8080

# File (-f targets.txt)
10.0.0.1
10.0.0.2:8000
192.168.1.0/24
# this is a comment
api.example.com
```

---

## Output

### Terminal (default)

```
[CRITICAL] 203.0.113.42:8000  /mcp  streamable_http  v=2025-06-18  no-auth
           server="internal-tools/1.2.3"  tools=7
           ⚠ rce_tool:execute_command
           ⚠ cloud_control:k8s_pods_exec(k8s)
           honeypot=false(score=5)

[HIGH]     203.0.113.10:3000  /sse  http_sse_legacy  v=2024-11-05  no-auth
           server="crm-agent/2.1"  tools=12
           ⚠ db_access:execute_sql
           ⚠ credential_in_metadata:get_customers
           honeypot=false(score=10)

[HONEYPOT] 1.2.3.4:8080  /mcp
           suspected=true(score=60)
           signals: invalid_version_accepted:9999-99-99, session_id_identical:honeypot-fixe

=== AgentScan Summary ===
Total MCP servers found: 3
  CRITICAL : 1
  HIGH     : 1
  MEDIUM   : 0
  LOW      : 0
  INFO     : 0
Honeypots  : 1
```

### JSON

```json
{
  "version": "1.0",
  "summary": {
    "total": 3,
    "by_risk": {"CRITICAL": 1, "HIGH": 1},
    "honeypots": 1
  },
  "results": [
    {
      "ip": "203.0.113.42",
      "port": 8000,
      "endpoint": "/mcp",
      "transport": "streamable_http",
      "protocol_version": "2025-06-18",
      "no_auth": true,
      "server_name": "internal-tools",
      "tool_count": 7,
      "risk_level": "CRITICAL",
      "risk_score": 80,
      "risk_reasons": ["unauthenticated_access", "rce_tool:execute_command"],
      "mitre": ["T1059", "T1059.004"]
    }
  ]
}
```

---

## Risk Levels

| Level | Trigger conditions | Example tools |
|-------|-------------------|---------------|
| **CRITICAL** | RCE tool names, cloud/K8s control, dangerous params (cmd/shell/exec) | `execute_command`, `k8s_pods_exec`, `run_script` |
| **HIGH** | Database access, credential leakage in metadata, SSRF params | `execute_sql`, `query_database`, AWS key in description |
| **MEDIUM** | SSRF params (url/webhook/callback) | `fetch_url(url)`, `send_webhook(endpoint)` |
| **LOW** | Read-only tools with no risky patterns | `list_files`, `search_docs` |
| **INFO** | Server online, tools not enumerable (authenticated) | — |

Detection rules are ported from [honeymcp](https://github.com/kosiorkosa47/honeymcp) (`secret_exfil.rs`) and [MCPScan](https://github.com/sahiloj/MCPScan) (`rce-vectors.ts`).

---

## Honeypot Detection

AgentScan detects decoy servers using two signals derived from Bitsight's analysis of 1,100+ honeypots:

| Signal | Score | Description |
|--------|-------|-------------|
| `invalid_version_accepted` | +20 | Server accepts `protocolVersion: "9999-99-99"` without error (spec requires rejection) |
| `session_id_identical` | +40 | Two separate `initialize` calls return the same `MCP-Session-Id` (spec requires globally unique IDs) |

Score ≥ 40 → `suspected_honeypot: true` (shown but not filtered by default; use `--exclude-honeypots` to filter).

---

## Internet Mapping (Shodan / FOFA / ZoomEye)

The following queries can be used with internet scanning platforms to enumerate publicly exposed MCP servers for research purposes. **Do not scan systems without authorization.**

### Shodan

```
# Highest precision — MCP-specific HTTP header
"MCP-Protocol-Version"

# Version string in response body
"protocolVersion" "2024-11-05"
"protocolVersion" "2025-03-26"
"protocolVersion" "2025-06-18"
"protocolVersion" "2025-11-25"

# serverInfo field (unique to MCP initialize response)
"serverInfo" "protocolVersion"

# Transport characteristics
port:8000 "jsonrpc" "tools"
port:3000 "text/event-stream" "jsonrpc"
port:8080 "text/event-stream" "mcp"

# Framework fingerprints
"uvicorn" "mcp"
"fastmcp"
http.title:"MCP Server"
```

### FOFA

```
# Most precise — MCP session header
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
# Header search
http.header="MCP-Protocol-Version"

# Body + header combination
http.header="text/event-stream" +http.body="jsonrpc" +http.body="protocolVersion"

# Framework
http.header.server="uvicorn" +http.body="mcp"
```

### Censys

> ⚠️ Censys only indexes the first **2 KB** of HTTP response bodies. MCP `initialize` responses often exceed this limit, so body-based searches have high miss rates. Header-based searches are more reliable.

```
# Services HTTP header search
services.http.response.headers: (key="Content-Type" and value="text/event-stream")

# Body search (limited to 2 KB)
services.http.response.body: "serverInfo"
```

**Platform recommendation by target:**
- International targets: **Shodan** (industry standard, widest MCP community adoption)
- Chinese domestic targets: **FOFA** (dominant domestic coverage, better WAF bypass)
- Avoid Censys for body-based MCP detection (2 KB body index limit causes significant miss rate)

---

## Legal & Ethics

> **This tool is for authorized security testing only.**
> Scanning systems without permission may violate computer fraud and abuse laws in your jurisdiction.

- Never invoke `tools/call` on discovered servers — AgentScan only calls `tools/list`
- After finding exposed servers, follow responsible disclosure: contact the owner, allow 90 days to fix before public disclosure
- The `--agree-tos` flag skips the legal confirmation prompt (intended for CI/CD pipelines scanning your own infrastructure)

---

## How It Works

```
Input (IP / CIDR / domain / file)
  │
  ▼ Stage 1: Target parsing
  │
  ▼ Stage 2: TCP port scan   (goroutine + semaphore, 500ms timeout)
     Ports: 80 443 8000 8080 8443 3000 3001 4000 5000 9000
  │
  ▼ Stage 3: HTTP filter     (GET /, check headers, 5s timeout)
  │
  ▼ Stage 4: MCP fingerprint (3-layer scoring, ≥0.65 = confirmed)
     Try: /mcp → /sse → / → /messages → /api/mcp → /v1/mcp
     L1: protocolVersion + MCP-specific capabilities (+0.5)
     L2: tools/list returns valid Tool schema (+0.2)
     L3: ping + notifications/initialized behavior (+0.3)
  │
  ▼ Stage 5: Deep analysis   (parallel)
     5A: Tool enumeration (tools/list, read-only)
     5B: Honeypot detection (2 signals)
     5C: Risk scoring (MITRE ATT&CK mapped)
  │
  ▼ Output: terminal / JSON
```

---

## Related Research

| Source | Key finding |
|--------|-------------|
| [arXiv:2605.22333](https://arxiv.org/abs/2605.22333) (2026-05) | 7,973 live MCP servers scanned; 40.55% unauthenticated; 9 CVEs |
| [arXiv:2510.16558](https://arxiv.org/abs/2510.16558) (DSN 2026) | Two-stage attack surface model; 833 vulnerable servers in 67,057 |
| [arXiv:2601.17549](https://arxiv.org/abs/2601.17549) | Protocol version downgrade vulnerabilities; +23–41% attack success rate |
| [Bitsight TRACE](https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities) (2025-12) | ~1,000 exposed; 1,100+ honeypots identified with fixed session IDs |
| [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud) (2026-04) | 1,467 exposed; CVSS 9.8 in AWS/Azure MCP servers; cloud account takeover |

---

## License

MIT — see [LICENSE](LICENSE)

---

## Disclaimer

AgentScan is provided for **authorized security testing and research only**.  
The authors are not responsible for any misuse or damage caused by this tool.
