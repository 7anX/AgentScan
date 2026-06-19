package models

import (
	"encoding/json"
	"time"
)

// LLMServer represents a confirmed LLM inference API endpoint finding.
type LLMServer struct {
	IP               string          `json:"ip"`
	Port             int             `json:"port"`
	Hostname         string          `json:"hostname,omitempty"`
	URL              string          `json:"url"`
	ServiceType      string          `json:"service_type"`       // "llm_inference_api"
	Framework        string          `json:"framework"`          // template info.name
	FrameworkVersion string          `json:"framework_version,omitempty"`
	Models           []LLMModel      `json:"models,omitempty"`
	ModelCount       int             `json:"model_count"`
	AuthStatus       string          `json:"auth_status"`        // "open" | "auth_required" | "unknown"
	FingerprintScore float64         `json:"fingerprint_score"`
	TLSEnabled       bool            `json:"tls_enabled"`
	ResponseTimeMs   float64         `json:"response_time_ms"`
	ScanTime         time.Time       `json:"scan_time"`
	Evidence         LLMEvidence     `json:"evidence,omitempty"`
	RawResponse      json.RawMessage `json:"raw_response,omitempty"`
}

// LLMModel represents a single model available on an LLM endpoint.
type LLMModel struct {
	ID      string `json:"id"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// LLMEvidence is the per-finding proof chain.
type LLMEvidence struct {
	MatchedEndpoints []LLMEndpointEvidence `json:"matched_endpoints,omitempty"`
	NegativeSignals  []string              `json:"negative_signals,omitempty"`
	AuthReasons      []string              `json:"auth_reasons,omitempty"`
}

// LLMEndpointEvidence captures proof from a single probed endpoint.
type LLMEndpointEvidence struct {
	Method             string  `json:"method"`
	Path               string  `json:"path"`
	StatusCode         int     `json:"status_code"`
	Matched            bool    `json:"matched"`
	ResponseMs         float64 `json:"response_ms"`
	ResponseFieldCount int     `json:"response_field_count,omitempty"` // top-level JSON fields
}
