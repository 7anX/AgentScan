package models

import (
	"encoding/json"
	"time"
)

type A2AProfile string

const (
	A2AProfileAgentCard       A2AProfile = "confirmed_a2a_agent_card"
	A2AProfileLegacyAgentJSON A2AProfile = "confirmed_a2a_legacy_agent_json"
	A2AProfileProbable        A2AProfile = "probable_agent_discovery"
)

type A2AInterfaceStatus string

const (
	A2AStatusUnknown                  A2AInterfaceStatus = "unknown"
	A2AStatusNoAuthJSONRPCReachable   A2AInterfaceStatus = "no_auth_jsonrpc_reachable"
	A2AStatusAuthRequired             A2AInterfaceStatus = "auth_required"
	A2AStatusEndpointDisabled         A2AInterfaceStatus = "a2a_endpoint_disabled"
	A2AStatusMethodNotAllowedNonRPC   A2AInterfaceStatus = "method_not_allowed_non_jsonrpc"
	A2AStatusNetworkError             A2AInterfaceStatus = "network_error"
	A2AStatusNoAuthStructuredRPCError A2AInterfaceStatus = "no_auth_jsonrpc_structured_error"
	// Extended card interface statuses
	A2AStatusExtendedCardNoAuth       A2AInterfaceStatus = "extended_card_no_auth"
	A2AStatusExtendedCardAuthRequired A2AInterfaceStatus = "extended_card_auth_required"
	A2AStatusExtendedCardNotFound     A2AInterfaceStatus = "extended_card_not_found"
)

type A2AExposureStatus string

const (
	A2AExposureCardPublic      A2AExposureStatus = "card_public_a2a"
	A2AExposureJSONRPCNoAuth   A2AExposureStatus = "confirmed_a2a_jsonrpc_no_auth"
	A2AExposureAuthRequired    A2AExposureStatus = "confirmed_a2a_auth_required"
	A2AExposureDisabled        A2AExposureStatus = "disabled_or_placeholder"
	A2AExposureProbable        A2AExposureStatus = "probable_agent_discovery"
	A2AExposureNonA2ADiscovery A2AExposureStatus = "non_a2a_agent_discovery"
)

type A2ASkill struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	InputModes  []string `json:"input_modes,omitempty"`
	OutputModes []string `json:"output_modes,omitempty"`
}

type A2ACapabilities struct {
	Streaming              interface{} `json:"streaming,omitempty"`
	PushNotifications      interface{} `json:"push_notifications,omitempty"`
	StateTransitionHistory interface{} `json:"state_transition_history,omitempty"`
	ExtendedAgentCard      interface{} `json:"extended_agent_card,omitempty"`
	Extensions             interface{} `json:"extensions,omitempty"`
	Raw                    interface{} `json:"raw,omitempty"`
}

type A2AInterface struct {
	URL                   string             `json:"url"`
	AdvertisedURL         string             `json:"advertised_url,omitempty"`
	Source                string             `json:"source,omitempty"`
	Binding               string             `json:"binding,omitempty"`
	ProtocolVersion       string             `json:"protocol_version,omitempty"`
	CrossHost             bool               `json:"cross_host,omitempty"`
	PrivateHostAdvertised bool               `json:"private_host_advertised,omitempty"`
	Status                A2AInterfaceStatus `json:"status,omitempty"`
	HTTPStatus            int                `json:"http_status,omitempty"`
	ErrorCode             string             `json:"error_code,omitempty"`
	ErrorMessage          string             `json:"error_message,omitempty"`
}

type A2AFingerprintEvidence struct {
	Score     float64    `json:"score"`
	Profile   A2AProfile `json:"profile,omitempty"`
	Signals   []string   `json:"signals,omitempty"`
	Negatives []string   `json:"negatives,omitempty"`
}

type A2ACardEvidence struct {
	URL             string            `json:"url,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

type A2AAuthEvidence struct {
	Declared string   `json:"declared,omitempty"`
	Status   string   `json:"status,omitempty"`
	Reasons  []string `json:"reasons,omitempty"`
}

type A2AEvidence struct {
	Card        A2ACardEvidence        `json:"card,omitempty"`
	Fingerprint A2AFingerprintEvidence `json:"fingerprint,omitempty"`
	Auth        A2AAuthEvidence        `json:"auth,omitempty"`
}

type A2AServer struct {
	IP               string                 `json:"ip"`
	Port             int                    `json:"port"`
	Hostname         string                 `json:"hostname,omitempty"`
	URL              string                 `json:"url"`
	CardURL          string                 `json:"card_url"`
	CardPath         string                 `json:"card_path"`
	Profile          A2AProfile             `json:"profile"`
	ExposureStatus   A2AExposureStatus      `json:"exposure_status,omitempty"`
	ExposureSignals  []string               `json:"exposure_signals,omitempty"`
	A2AConfirmed     bool                   `json:"a2a_confirmed"`
	FingerprintScore float64                `json:"fingerprint_score"`
	NoAuth           bool                   `json:"no_auth"`
	AuthRequired     bool                   `json:"auth_required,omitempty"`
	EndpointDisabled bool                   `json:"endpoint_disabled,omitempty"`
	AgentName        string                 `json:"agent_name,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Version          string                 `json:"version,omitempty"`
	ProtocolVersion  string                 `json:"protocol_version,omitempty"`
	Provider         map[string]interface{} `json:"provider,omitempty"`
	Capabilities     A2ACapabilities        `json:"capabilities,omitempty"`
	Skills           []A2ASkill             `json:"skills,omitempty"`
	SkillCount       int                    `json:"skill_count"`
	Interfaces       []A2AInterface         `json:"interfaces,omitempty"`
	ScanTime         time.Time              `json:"scan_time"`
	ResponseTimeMs   float64                `json:"response_time_ms"`
	TLSEnabled       bool                   `json:"tls_enabled"`
	Evidence         A2AEvidence            `json:"evidence,omitempty"`
	RawCardResponse  json.RawMessage        `json:"raw_card_response,omitempty"`
	Error            string                 `json:"error,omitempty"`
}
