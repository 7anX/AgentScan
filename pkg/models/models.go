package models

import (
	"encoding/json"
	"time"

	"github.com/agentscan/agentscan/pkg/config"
)

// Transport MCP 传输类型
type Transport string

const (
	TransportStreamableHTTP Transport = "streamable_http"
	TransportHTTPSSELegacy  Transport = "http_sse_legacy"
)

// MCPTool 单个工具定义
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// MCPResource 单个资源定义（resources/list）
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// MCPPrompt 单个提示词定义（prompts/list）
type MCPPrompt struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// MCPResourceTemplate 资源模板定义（resources/templates/list）
type MCPResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// MCPCapabilities capabilities 结构
type MCPCapabilities struct {
	Tools        interface{} `json:"tools,omitempty"`
	Resources    interface{} `json:"resources,omitempty"`
	Prompts      interface{} `json:"prompts,omitempty"`
	Logging      interface{} `json:"logging,omitempty"`
	Sampling     interface{} `json:"sampling,omitempty"`
	Completions  interface{} `json:"completions,omitempty"`
	Experimental interface{} `json:"experimental,omitempty"`
}

// HoneypotResult 蜜罐检测结果
type HoneypotResult struct {
	Suspected bool     `json:"suspected"`
	Score     int      `json:"score"`
	Signals   []string `json:"signals,omitempty"`
}

// JSONRPCSummary records the small, reproducible part of a JSON-RPC response.
type JSONRPCSummary struct {
	RequestMethod string   `json:"request_method,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	HasResult     bool     `json:"has_result"`
	ResultKeys    []string `json:"result_keys,omitempty"`
	HasError      bool     `json:"has_error"`
	ErrorCode     string   `json:"error_code,omitempty"`
	ErrorMessage  string   `json:"error_message,omitempty"`
}

// FingerprintEvidence explains why a response was classified as MCP.
type FingerprintEvidence struct {
	Score   float64  `json:"score"`
	Signals []string `json:"signals,omitempty"`
}

// AuthEvidence explains the auth/no-auth classification.
type AuthEvidence struct {
	Status  string   `json:"status,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

// MCPEvidence is the per-finding proof chain used by JSON/HTML/TXT reports.
type MCPEvidence struct {
	URL              string              `json:"url,omitempty"`
	Transport        Transport           `json:"transport,omitempty"`
	ProtocolVersion  string              `json:"protocol_version,omitempty"`
	ResponseHeaders  map[string]string   `json:"response_headers,omitempty"`
	JSONRPC          JSONRPCSummary      `json:"jsonrpc,omitempty"`
	Fingerprint      FingerprintEvidence `json:"fingerprint,omitempty"`
	Auth             AuthEvidence        `json:"auth,omitempty"`
	ResponseTimeMs   float64             `json:"response_time_ms,omitempty"`
	ResolvedPostPath string              `json:"resolved_post_path,omitempty"`
}

// MCPServer 扫描结果（只保留存活信息，不做风险评估）
type MCPServer struct {
	IP                    string                `json:"ip"`
	Port                  int                   `json:"port"`
	Hostname              string                `json:"hostname,omitempty"`
	URL                   string                `json:"url"`
	Endpoint              string                `json:"endpoint"`
	Transport             Transport             `json:"transport"`
	FingerprintScore      float64               `json:"fingerprint_score"`
	NoAuth                bool                  `json:"no_auth"`
	AuthRequired          bool                  `json:"auth_required,omitempty"`
	ServerName            string                `json:"server_name,omitempty"`
	ServerVersion         string                `json:"server_version,omitempty"`
	ProtocolVersion       string                `json:"protocol_version,omitempty"`
	Capabilities          MCPCapabilities       `json:"capabilities"`
	SessionID             string                `json:"session_id,omitempty"`
	Tools                 []MCPTool             `json:"tools,omitempty"`
	ToolCount             int                   `json:"tool_count"`
	Resources             []MCPResource         `json:"resources,omitempty"`
	ResourceCount         int                   `json:"resource_count"`
	ResourceTemplates     []MCPResourceTemplate `json:"resource_templates,omitempty"`
	ResourceTemplateCount int                   `json:"resource_template_count"`
	Prompts               []MCPPrompt           `json:"prompts,omitempty"`
	PromptCount           int                   `json:"prompt_count"`
	Honeypot              HoneypotResult        `json:"honeypot"`
	ScanTime              time.Time             `json:"scan_time"`
	ResponseTimeMs        float64               `json:"response_time_ms"`
	TLSEnabled            bool                  `json:"tls_enabled"`
	Evidence              MCPEvidence           `json:"evidence,omitempty"`
	RawInitResponse       json.RawMessage       `json:"raw_init_response,omitempty"`
	Error                 string                `json:"error,omitempty"`
}

// ScanConfig 扫描配置
type ScanConfig struct {
	// Ports 是本次扫描实际使用的端口列表（"最终值"）。
	// 初始化顺序：DefaultConfig/DefaultA2AConfig 从 Dict 设置协议对应默认端口；
	// 若用户显式传 --ports，main.go 会再用 parsePorts() 覆盖此字段。
	// 流水线只读此字段做端口扫描，不再读 Dict.MCPPorts / Dict.A2APorts。
	//
	// Dict 是字典模板，用于 HTTP 过滤阶段（HTTPSPorts 推断、MCPServerHints 匹配、
	// 路径探测列表等），与 Ports 语义不同，不应混用。
	Ports            []int
	Concurrency      int
	TimeoutConnectMs int
	TimeoutHTTPMs    int
	TimeoutMCPMs     int
	MCPConcurrency   int  // MCP/A2A 探测并发数（默认 50，可通过 --mcp-threads/--a2a-threads 调整）
	SkipPortScan     bool // 跳过 TCP 端口扫描，适用于输入已知 IP:Port 列表的场景
	ExcludeHoneypots bool
	VerboseRaw       bool
	Verbose          bool            // 详细日志：打印每个开放端口、每个探测过程、耗时
	Dict             *config.DictSet // 解耦字典集合；nil 时各模块应调用 config.DefaultDictSet()
	Proxy            string          // 可选代理：(socks5|socks4|https|http)://host:port
}

// DefaultConfig MCP 扫描默认配置（数值来自 pkg/config/config.go，统一在那里修改）
func DefaultConfig() ScanConfig {
	ds := config.DefaultDictSet()
	return ScanConfig{
		Ports:            ds.MCPPorts,
		Concurrency:      config.DefaultConcurrency,
		TimeoutConnectMs: config.DefaultTimeoutConnectMs,
		TimeoutHTTPMs:    config.DefaultTimeoutConnectMs * 10,
		TimeoutMCPMs:     config.DefaultTimeoutConnectMs * 20,
		MCPConcurrency:   50,
		Dict:             ds,
	}
}

// DefaultA2AConfig A2A 扫描默认配置
func DefaultA2AConfig() ScanConfig {
	ds := config.DefaultDictSet()
	return ScanConfig{
		Ports:            ds.A2APorts,
		Concurrency:      config.DefaultConcurrency,
		TimeoutConnectMs: config.DefaultTimeoutConnectMs,
		TimeoutHTTPMs:    config.DefaultTimeoutConnectMs * 10,
		TimeoutMCPMs:     config.DefaultTimeoutConnectMs * 20,
		MCPConcurrency:   50,
		Dict:             ds,
	}
}
