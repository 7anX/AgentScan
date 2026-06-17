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

// MCPServer 扫描结果（只保留存活信息，不做风险评估）
type MCPServer struct {
	IP               string          `json:"ip"`
	Port             int             `json:"port"`
	Hostname         string          `json:"hostname,omitempty"`
	URL              string          `json:"url"`
	Endpoint         string          `json:"endpoint"`
	Transport        Transport       `json:"transport"`
	FingerprintScore float64         `json:"fingerprint_score"`
	NoAuth           bool            `json:"no_auth"`
	AuthRequired     bool            `json:"auth_required,omitempty"`
	ServerName       string          `json:"server_name,omitempty"`
	ServerVersion    string          `json:"server_version,omitempty"`
	ProtocolVersion  string          `json:"protocol_version,omitempty"`
	Capabilities     MCPCapabilities `json:"capabilities"`
	SessionID        string          `json:"session_id,omitempty"`
	Tools            []MCPTool       `json:"tools,omitempty"`
	ToolCount        int             `json:"tool_count"`
	Resources             []MCPResource        `json:"resources,omitempty"`
	ResourceCount         int                  `json:"resource_count"`
	ResourceTemplates     []MCPResourceTemplate `json:"resource_templates,omitempty"`
	ResourceTemplateCount int                  `json:"resource_template_count"`
	Prompts               []MCPPrompt          `json:"prompts,omitempty"`
	PromptCount           int                  `json:"prompt_count"`
	Honeypot         HoneypotResult  `json:"honeypot"`
	ScanTime         time.Time       `json:"scan_time"`
	ResponseTimeMs   float64         `json:"response_time_ms"`
	TLSEnabled       bool            `json:"tls_enabled"`
	RawInitResponse  json.RawMessage `json:"raw_init_response,omitempty"`
	Error            string          `json:"error,omitempty"`
}

// ScanConfig 扫描配置
type ScanConfig struct {
	Ports            []int
	Concurrency      int
	TimeoutConnectMs int
	TimeoutHTTPMs    int
	TimeoutMCPMs     int
	ExcludeHoneypots bool
	VerboseRaw       bool
	Verbose          bool // 详细日志：打印每个开放端口、每个MCP探测过程、耗时
}

// DefaultConfig 默认配置（数值来自 pkg/config/config.go，统一在那里修改）
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Ports:            config.DefaultPorts,
		Concurrency:      config.DefaultConcurrency,
		TimeoutConnectMs: config.DefaultTimeoutConnectMs,
		TimeoutHTTPMs:    config.DefaultTimeoutConnectMs * 10,
		TimeoutMCPMs:     config.DefaultTimeoutConnectMs * 20,
	}
}