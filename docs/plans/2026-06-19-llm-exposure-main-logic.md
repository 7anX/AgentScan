# AgentScan LLM Inference API 暴露面扫描主逻辑方案

日期：2026-06-19

---

## 目标

为 AgentScan 增加 LLM Inference API 暴露面识别能力，覆盖 Ollama、vLLM、SGLang、llama.cpp、TGI、LocalAI、Xinference、LiteLLM、FastChat、LM Studio、LMDeploy 等常见推理服务。

扫描模块只做只读探测，不触发推理、不创建任务、不拉取模型、不修改服务状态。

---

## 与现有代码的集成关系

### 现有流水线结构（MCP / A2A 共用）

```
target parse
  -> port scan           (ScanPorts)
  -> HTTP candidate filter (FilterHTTP)   → []HTTPCandidate
  -> MCP probe           (Pipeline.RunFromCandidates)
  -> A2A probe           (A2APipeline.RunFromCandidates)
```

LLM 模块以相同模式接入：

```
target parse
  -> port scan           (ScanPorts，复用)
  -> HTTP candidate filter (FilterHTTP，复用)   → []HTTPCandidate
  -> MCP probe
  -> A2A probe
  -> LLM probe           (LLMPipeline.RunFromCandidates，新增)
  -> unified report
```

### 新增文件清单

```
pkg/models/llm.go              LLMServer、LLMProbeResult、LLMRiskLevel 等结构体
pkg/scanner/llm_probe.go       Stage1 / Stage2 探测、指纹判定、误报过滤
pkg/scanner/llm_pipeline.go    LLMPipeline（复用 Pipeline 并发骨架）
pkg/output/llm.go              PrintLLMServer、PrintLLMSummary、WriteLLMJSON
dicts/llm_ports.txt            P0/P1/P2 端口分层列表
```

### config.go 补充

在 `pkg/config/config.go` 末尾追加 LLM 端口列表（与 `DefaultPorts`、`A2ADefaultPorts` 同级）：

```go
// LLMDefaultPorts LLM 推理服务默认扫描端口（按命中率降序）。
//
// P0 — 各框架官方默认端口，必扫：
//   11434  Ollama
//   8000   vLLM / FastChat API / TensorRT-LLM
//   8080   LocalAI / llama.cpp / KoboldCpp
//   3000   TGI (text-generation-inference)
//   1234   LM Studio
//   4000   LiteLLM Proxy
//
// P1 — 次级框架或特殊部署：
//   9997   Xinference
//   30000  SGLang
//   5001   KoboldAI
//   4891   GPT4All
//   23333  LMDeploy（上海 AI Lab）
//   21001  FastChat Controller
//   21002  FastChat Worker
//
// P2 — 非标端口（实测发现 / 端口冲突后移）：
//   8001   Triton HTTP
//   5000   Flask 封装
//   7860   Gradio 包装层
//   20128  实测发现（题目中已确认）
//   11435  Ollama 多实例（端口冲突后递增）
var LLMDefaultPorts = []int{
    11434, 8000, 8080, 3000, 1234, 4000,
    9997, 30000, 5001, 4891, 23333, 21001, 21002,
    8001, 5000, 7860, 20128, 11435,
}
```

`models.go` 补充 `DefaultLLMConfig()`，参照 `DefaultA2AConfig()` 的写法。

---

## 端口策略

端口只用于生成候选，不用于确认 LLM 服务类型。确认必须依赖 HTTP 响应结构。

```
P0（必扫）:   11434, 8000, 8080, 3000, 1234, 4000
P1（建议扫）: 9997, 30000, 5001, 4891, 23333, 21001, 21002
P2（可选）:   8001, 5000, 7860, 20128, 11435
```

**注意：** P0 中 8000 / 8080 / 3000 与现有 MCP 端口重叠，`agentscan scan` 模式下端口扫描只做一次，三个探测器共享 `[]HTTPCandidate`。

---

## 探测边界

### 允许（全部 GET，零副作用）

```
/v1/models
/
/api/version
/api/tags
/api/ps
/info
/health
/version
/metrics
/readyz
/healthz
/v1/cluster/auth
/v1/cluster/info
/props
/slots
/health/liveliness
/health/readiness
/get_model_info
/list_models
/worker_get_status
```

### 禁止（有副作用或高危）

```
POST /v1/chat/completions
POST /v1/completions
POST /v1/embeddings
POST /generate
POST /generate_stream
POST /api/generate
POST /api/chat
POST /api/create
POST /api/pull
POST /api/push
DELETE /api/delete
```

---

## 主扫描流程

### 候选生成

与 MCP / A2A 完全一致，复用 `ScanPorts` + `FilterHTTP`：

```
if --skip-port-scan:
    treat all input as known open host:port or URL
else:
    scan LLMDefaultPorts

FilterHTTP -> []HTTPCandidate{IP, Port, Hostname, BaseURL, Scheme}
```

HTTP/HTTPS 规则沿用现有逻辑：
- 用户指定 scheme 时优先使用
- 未指定时按端口推断（参考 `dicts/https_ports.txt`）
- Stage 1 全部连接失败时切换 HTTP/HTTPS 再试一次
- 只允许同主机、同端口、HTTP→HTTPS 的一次重定向

### Stage 1 — 主探测

对每个 `HTTPCandidate` 并发请求高收益端点：

```
GET /v1/models
GET /
GET /api/version
GET /api/tags
GET /info
```

**Stage 1 目标：**
- 快速确认 OpenAI-compatible 服务（`/v1/models` 返回合法 model list）
- 快速确认 Ollama（`/` 返回 "Ollama is running"）
- 快速确认 TGI（`/info` 含 `max_total_tokens` + `model_dtype`）
- 判断认证状态（200 vs 401/403）
- 决定是否进入 Stage 2

**进入 Stage 2 的条件（满足任一）：**

```
/v1/models == 200  AND valid model list JSON
/v1/models == 401 or 403  AND body contains auth-error keyword
/ contains "Ollama is running"
/api/version returns {"version":"..."}
/api/tags returns {"models":[...]}
/info contains {model_id, max_total_tokens, model_dtype}
```

**不进入 Stage 2（直接丢弃）：**

```
Stage 1 全部超时或连接失败
/v1/models 返回 HTML
/v1/models 返回 404 File Not Found
全部路径返回相同 HTML（same-body 检测）
全部路径重定向且无 LLM JSON
```

### Stage 2 — 框架分流

仅 Stage 1 有有效线索时请求：

```
GET /health
GET /version
GET /readyz
GET /healthz
GET /metrics
GET /v1/cluster/auth
GET /v1/cluster/info
GET /props
GET /slots
GET /health/liveliness
GET /health/readiness
GET /get_model_info
GET /list_models
GET /worker_get_status
```

**Stage 2 目标：**
- 区分 vLLM 和 SGLang（两者都可能有 `max_model_len`）
- 识别 Xinference、llama.cpp、LiteLLM、FastChat
- 通过 `/version`、`/metrics`、`/props` 补充版本和置信度
- 最终确定 `auth_status` 和 `risk_level`

---

## 指纹判定逻辑

### fingerprint_score 计算规则

```
1.00  专有端点或唯一字段（单信号即可确认）
      Ollama:      GET / → "Ollama is running"
      TGI:         GET /info → {max_total_tokens, model_dtype}
      Xinference:  GET /v1/cluster/auth → {"auth": bool}
      llama.cpp:   GET /props → {total_slots}
      SGLang:      GET /get_model_info → {is_generation}

0.85  专有端点 + 已知 /v1/models 有效（双信号）
      上述框架同时有 /v1/models 200 响应时得分提升到 0.85+

0.75  字段组合，有一定排他性
      vLLM:        /v1/models data[].owned_by="vllm"  OR  /version 200
      LiteLLM:     /health/liveliness → {"status":"healthy"}
      LocalAI:     /v1/models data[].owned_by="local-ai"
      FastChat:    port=21001 AND /list_models 200

0.50  格式兼容，框架未确认
      vLLM-or-SGLang: max_model_len 存在但 /get_model_info 无响应且 /version 无响应
      OpenAI-Compatible: /v1/models 有效但无框架特征字段

0.30  弱信号，仅记录为 INFO
      仅 /version 存在（非 LLM 专属）
      仅 /health 200（非 LLM 专属）
```

`FingerprintScore < 0.35` 的结果不进入最终报告（与 MCP 阈值一致）。

### OpenAI-Compatible 确认

```
GET /v1/models == 200
JSON body.object == "list"
JSON body.data is array
data empty OR (data[i].object == "model" AND data[i].id is string)
Content-Type contains "application/json"
```

模型列表非空：`auth_status=open, risk=CRITICAL`
模型列表为空：`auth_status=open, risk=HIGH`

### 认证保护确认

```
/v1/models == 401 or 403
AND body contains one of:
    "api key" / "invalid api key" / "unauthorized" /
    "authentication" / "no key provided" / "bearer"
```

结果：`auth_status=auth_required, risk=MEDIUM`

### Ollama

**强指纹（score=1.00）：**
```
GET / response.text contains "Ollama is running"
```

**增强（score 提升到 1.00）：**
```
/api/version returns {"version":"x.x.x"}  （字段极少，≤3 个 key）
/api/tags returns {"models":[...]}
/api/ps returns {"models":[...]}
```

Ollama 强指纹优先级最高：即使 `/v1/models` 也有效，仍归类为 Ollama，不归 OpenAI-Compatible。

版本信息从 `/api/version` 的 `version` 字段提取。

### vLLM

**候选条件（满足任一）：**
```
/v1/models data[i].owned_by == "vllm"
/v1/models data[i].max_model_len 字段存在
```

**确认条件：**
```
GET /version returns {"version":"x.x.x"}
```

若只有 `max_model_len` 而 `/get_model_info` 不存在且 `/version` 无响应：
```
framework = "vLLM-or-SGLang"
fingerprint_score = 0.50
```

**半认证检测（vLLM 专属）：**
```
/v1/models == 401
AND /version == 200  （即使启用 --api-key 也无需认证）
→ auth_status = partially_open
→ risk = MEDIUM
```

vLLM Prometheus metrics 辅助确认：
```
GET /metrics contains "vllm:num_requests_running"
→ framework = vLLM，score += 0.1
```

### SGLang

**候选条件：**
```
/v1/models data[i].max_model_len 存在
```

**确认条件：**
```
GET /get_model_info returns JSON containing "is_generation" or "model_path"
```

SGLang 与 vLLM 存在字段重叠，`/get_model_info` 是唯一区分点。

### TGI

**确认条件（三字段同时存在）：**
```
GET /info returns JSON containing:
  "model_id"
  "max_total_tokens"
  "model_dtype"
```

从 `/info` 提取的扫描信息：`model_id`、`version`、`model_dtype`、`model_device_type`、`max_total_tokens`、`max_concurrent_requests`。

### LocalAI

**确认条件：**
```
/v1/models data[i].owned_by == "local-ai"
```

**辅助信号（不能单独确认）：**
```
GET /readyz == 200
GET /healthz == 200
```

两个辅助信号必须与 `/v1/models` 有效响应同时存在才计入 score。

### Xinference

**确认条件：**
```
GET /v1/cluster/auth returns JSON containing "auth" key
```

认证状态：
```
auth=false  → auth_status=open,          risk=CRITICAL/HIGH
auth=true   → auth_status=auth_required, risk=MEDIUM
```

### llama.cpp

**确认条件：**
```
GET /props returns JSON containing "total_slots"
  OR
GET /props returns JSON containing "default_generation_settings"
```

辅助确认：
```
GET /slots returns JSON array
```

### LiteLLM

**确认条件：**
```
GET /health/liveliness returns {"status":"healthy"}
```

`/health/liveliness` 无需认证（LiteLLM 设计行为），是唯一免认证专有端点。

若 `/v1/models` 为 401/403：
```
auth_status = partially_open
risk = MEDIUM
```

### FastChat

Controller（port 21001）：
```
GET /list_models returns JSON containing "models" or "model_names"
framework = FastChat-Controller
```

Worker（port 21002）：
```
GET /worker_get_status returns JSON containing "model_names", "status", or "speed"
framework = FastChat-Worker
```

非 21001/21002 端口上发现 FastChat 特征时，`fingerprint_score -= 0.15`。

---

## 误报排除

以下情况不生成结果（直接丢弃）：

```
仅端口开放，无任何 HTTP 响应
仅 GET / 返回 200（无 LLM JSON 或特征文本）
仅 /version 返回 200（version_only_signal）
/v1/models 返回 HTML
/v1/models body 含 "404 File Not Found"
所有探测路径返回相同 body（all_paths_same_body）
所有探测路径均重定向且无 LLM JSON（redirect_only）
根路径 JSON 为文件列表（root_json_file_listing）
普通登录页面
WAF / CDN 错误页面
```

记录 negative_signals（用于 evidence，不影响是否报告）：

```go
const (
    NegAllPathsSameBody      = "all_paths_return_same_body"
    NegModelEndpointHTML     = "model_endpoint_returns_html"
    NegRedirectOnly          = "redirect_only_without_llm_json"
    NegRootFilelisting        = "root_json_file_listing"
    NegVersionOnlySignal     = "version_only_signal"
    NegHealthOnlySignal      = "health_only_signal"
)
```

---

## 风险分级

```
CRITICAL:
  auth_status=open AND models_count > 0
  条件：/v1/models 非空 model list  OR  /api/tags 非空 models[]

HIGH:
  auth_status=open AND framework 已确认
  条件：服务在线但 models_count=0（模型未加载）

MEDIUM:
  auth_status=auth_required AND framework 已确认
  auth_status=partially_open（vLLM /version 可达 + /v1/models 401）
  LiteLLM partially_open

INFO:
  fingerprint_score in [0.35, 0.50)（弱信号，框架未确认）

NONE:
  fingerprint_score < 0.35（不输出）
```

默认只展示 `CRITICAL / HIGH / MEDIUM`。`INFO` 通过 `--verbose` 输出。

---

## 数据模型

### pkg/models/llm.go

```go
package models

import "time"

type LLMRiskLevel string

const (
    LLMRiskCritical LLMRiskLevel = "CRITICAL"
    LLMRiskHigh     LLMRiskLevel = "HIGH"
    LLMRiskMedium   LLMRiskLevel = "MEDIUM"
    LLMRiskInfo     LLMRiskLevel = "INFO"
    LLMRiskNone     LLMRiskLevel = "NONE"
)

type LLMAuthStatus string

const (
    LLMAuthOpen          LLMAuthStatus = "open"
    LLMAuthRequired      LLMAuthStatus = "auth_required"
    LLMAuthPartiallyOpen LLMAuthStatus = "partially_open"
    LLMAuthUnknown       LLMAuthStatus = "unknown"
)

// LLMModel 单个已加载模型的摘要信息
type LLMModel struct {
    ID           string  `json:"id"`
    OwnedBy      string  `json:"owned_by,omitempty"`
    Family       string  `json:"family,omitempty"`
    Size         int64   `json:"size,omitempty"`
    Quantization string  `json:"quantization,omitempty"`
    MaxModelLen  *int64  `json:"max_model_len,omitempty"`
}

// LLMProbeEndpoint Stage 1/2 单个端点探测记录
type LLMProbeEndpoint struct {
    Method     string   `json:"method"`
    Path       string   `json:"path"`
    StatusCode int      `json:"status_code"`
    Signals    []string `json:"signals,omitempty"`
}

// LLMEvidence 指纹证据链（对应 MCPEvidence / A2AEvidence 设计）
type LLMEvidence struct {
    Endpoints       []LLMProbeEndpoint `json:"endpoints,omitempty"`
    NegativeSignals []string           `json:"negative_signals,omitempty"`
    FingerprintScore float64           `json:"fingerprint_score"`
    FingerprintSignals []string        `json:"fingerprint_signals,omitempty"`
}

// LLMServer 扫描结果（对应 MCPServer / A2AServer）
type LLMServer struct {
    IP               string        `json:"ip"`
    Port             int           `json:"port"`
    Hostname         string        `json:"hostname,omitempty"`
    URL              string        `json:"url"`
    Framework        string        `json:"framework"`
    FrameworkVersion string        `json:"framework_version,omitempty"`
    AuthStatus       LLMAuthStatus `json:"auth_status"`
    ModelsCount      int           `json:"models_count"`
    Models           []LLMModel    `json:"models,omitempty"`
    RiskLevel        LLMRiskLevel  `json:"risk_level"`
    FingerprintScore float64       `json:"fingerprint_score"`
    ScanTime         time.Time     `json:"scan_time"`
    ResponseTimeMs   float64       `json:"response_time_ms"`
    TLSEnabled       bool          `json:"tls_enabled"`
    Evidence         LLMEvidence   `json:"evidence,omitempty"`
    Error            string        `json:"error,omitempty"`
}
```

### ScanConfig 扩展

在 `models.ScanConfig` 中追加 LLM 相关字段（或在 `DefaultLLMConfig()` 中单独初始化）：

```go
// DefaultLLMConfig LLM 扫描默认配置
func DefaultLLMConfig() ScanConfig {
    ds := config.DefaultDictSet()
    return ScanConfig{
        Ports:            config.LLMDefaultPorts,
        Concurrency:      config.DefaultConcurrency,
        TimeoutConnectMs: config.DefaultTimeoutConnectMs,
        TimeoutHTTPMs:    config.DefaultTimeoutConnectMs * 10,
        TimeoutMCPMs:     config.DefaultTimeoutConnectMs * 10, // LLM 探测无需 MCP 超时，复用字段名
        MCPConcurrency:   50,
        Dict:             ds,
    }
}
```

---

## 输出设计

### 终端输出（对应 output.PrintServer）

```
[LLM] 1.2.3.4:11434/       Ollama v0.5.0   open           CRITICAL  models=5  score=1.00
      evidence  / → ollama_running; /api/tags → ollama_models(5)

[LLM] 5.6.7.8:8000/v1      vLLM v0.6.1     open           CRITICAL  models=2  score=0.85
      evidence  /v1/models → openai_model_list; /version → vllm_version

[LLM] 9.0.0.1:8000/v1      vLLM            partially_open MEDIUM    models=0  score=0.75
      evidence  /v1/models → 401 auth_required; /version → vllm_version

[LLM] 2.3.4.5:9997/        Xinference      open           HIGH      models=0  score=1.00
      evidence  /v1/cluster/auth → {"auth":false}
```

### 输出文件

LLM 单独扫描（`agentscan llm`）：

```
llm_findings.txt        所有 CRITICAL/HIGH/MEDIUM 条目（纯文本）
llm_no_auth.txt         auth_status=open 条目
llm_auth_required.txt   auth_status=auth_required 条目
llm_models.txt          所有暴露模型 ID 列表（去重）
llm_results.json        完整结构化结果
report.html             HTML 报告
summary.txt             统计摘要
```

统一扫描（`agentscan scan`）：

```
mcp_*.txt / a2a_*.txt / llm_*.txt
report.html（含 MCP + A2A + LLM 三模块）
summary.txt
```

### llm_results.json 单条结构

```json
{
  "ip": "1.2.3.4",
  "port": 11434,
  "hostname": "example.com",
  "url": "http://1.2.3.4:11434",
  "framework": "Ollama",
  "framework_version": "0.5.0",
  "auth_status": "open",
  "models_count": 2,
  "models": [
    {"id": "llama3:latest", "family": "llama", "size": 4661211136},
    {"id": "qwen2.5:7b",    "family": "qwen",  "size": 4683735424}
  ],
  "risk_level": "CRITICAL",
  "fingerprint_score": 1.0,
  "scan_time": "2026-06-19T10:00:00Z",
  "tls_enabled": false,
  "response_time_ms": 42.5,
  "evidence": {
    "fingerprint_score": 1.0,
    "fingerprint_signals": ["ollama_running", "ollama_version", "ollama_models"],
    "endpoints": [
      {"method": "GET", "path": "/",         "status_code": 200, "signals": ["ollama_running"]},
      {"method": "GET", "path": "/api/version", "status_code": 200, "signals": ["ollama_version"]},
      {"method": "GET", "path": "/api/tags",  "status_code": 200, "signals": ["ollama_models"]}
    ],
    "negative_signals": []
  }
}
```

---

## 实现拆分

### pkg/scanner/llm_probe.go

职责：
- `ProbeLLM(ctx, baseURL, hostname, timeoutMs) *LLMProbeResult`
- Stage 1 请求（5 个端点并发）
- Stage 2 请求（按 Stage 1 线索触发，15 个端点并发）
- 指纹判定（`classifyFramework`）
- 误报过滤（`hasNegativeSignals`）
- 风险评级（`evaluateRisk`）

### pkg/scanner/llm_pipeline.go

职责：
- `LLMPipeline` struct，字段与 `Pipeline` / `A2APipeline` 对齐
- `NewLLMPipeline(cfg, noColor, onFound) *LLMPipeline`
- `RunFromCandidates(ctx, []HTTPCandidate) []*models.LLMServer`
- 并发骨架直接复制 `a2a_pipeline.go:RunFromCandidates`，替换类型即可
- 按 `FingerprintScore` 降序排列结果

### pkg/output/llm.go

职责：
- `PrintLLMServer(s *models.LLMServer, noColor bool)`
- `PrintLLMSummary(servers []*models.LLMServer, noColor bool)`
- `WriteLLMJSON(servers []*models.LLMServer, path string) error`
- `WriteLLMTXT(servers []*models.LLMServer, dir string) error`

### pipeline.go 修改（RunScan）

在 A2A probe 完成后追加 LLM probe：

```go
// LLM probe — reuse the same HTTP candidates
var llmResults []*models.LLMServer
if len(candidates) > 0 {
    fmt.Fprintf(os.Stderr, "\n--- LLM scan ---\n")
    llmPipeline := NewLLMPipeline(cfg, noColor, llmOnFound)
    llmPipeline.probeLabel = "--- LLM probe    "
    llmResults = llmPipeline.RunFromCandidates(ctx, candidates)
    // output + report...
}
```

---

## 测试策略

本地 mock 回归用例（覆盖所有框架 + 误报场景）：

```
Ollama open（有模型）
Ollama open（无模型）
vLLM open
vLLM auth_required（/v1/models 401 + /version 200）
vLLM-or-SGLang（max_model_len 存在，无法区分）
SGLang open
TGI open
LocalAI open
Xinference open (auth=false)
Xinference auth_required (auth=true)
llama.cpp open
LiteLLM partially_open
FastChat Controller (port 21001)
FastChat Worker (port 21002)
普通 HTML 网站（不报告）
/v1/models 返回 HTML（不报告）
全部路径返回相同 body（不报告）
仅 /version 存在（不报告）
/v1/models 返回空 data[]（报告为 HIGH）
```

通过标准：

```
真实 LLM 框架能确认，framework 字段正确
认证保护能报告 MEDIUM
部分认证（vLLM）能报告 partially_open
普通网站不产生结果
全路径 same-body 不产生结果
仅 /version 存在不产生结果
fingerprint_score 与预期值误差 < 0.05
```
