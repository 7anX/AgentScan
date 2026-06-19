package llmtpl

// Template represents one LLM framework fingerprint template loaded from YAML.
// Format is inspired by AI-Infra-Guard's fingerprint schema, extended with
// stage2, auth, risk, models, and negatives sections.
type Template struct {
	Info      TemplateInfo  `yaml:"info"`
	HTTP      []HTTPRule    `yaml:"http"`             // Stage 1 probes
	Stage2    []HTTPRule    `yaml:"stage2,omitempty"` // Stage 2 probes (run only if stage1 has signal)
	Version   []VersionRule `yaml:"version,omitempty"`
	Models    []ModelRule   `yaml:"models,omitempty"`
	Auth      *AuthRule     `yaml:"auth,omitempty"`
	Risk      *RiskMatrix   `yaml:"risk,omitempty"`
	Negatives []string      `yaml:"negatives,omitempty"` // DSL expressions; match → exclude this framework
}

// TemplateInfo holds metadata about the template.
type TemplateInfo struct {
	Name     string            `yaml:"name"`
	Author   string            `yaml:"author,omitempty"`
	Severity string            `yaml:"severity"` // critical | high | medium | info
	Desc     string            `yaml:"desc,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
	Priority int               `yaml:"priority,omitempty"` // disambiguation priority (lower = higher priority, default 50)
}

// HTTPRule defines one HTTP probe with its matchers (DSL expressions).
// Matchers within a rule have OR semantics: if any matcher matches, the rule is satisfied.
type HTTPRule struct {
	Method   string   `yaml:"method"`            // GET | POST
	Path     string   `yaml:"path"`              // e.g. "/v1/models"
	Matchers []string `yaml:"matchers"`          // DSL expression list (OR relation)
	Data     string   `yaml:"data,omitempty"`    // POST request body
}

// VersionRule defines how to extract the framework version.
type VersionRule struct {
	Method    string    `yaml:"method"`
	Path      string    `yaml:"path"`
	Matchers  []string  `yaml:"matchers,omitempty"` // optional precondition
	Extractor Extractor `yaml:"extractor"`
}

// ModelRule defines how to extract the model list.
type ModelRule struct {
	Method    string         `yaml:"method"`
	Path      string         `yaml:"path"`
	Matchers  []string       `yaml:"matchers,omitempty"`
	Extractor ModelExtractor `yaml:"extractor"`
}

// Extractor defines regex-based value extraction (for version).
type Extractor struct {
	Part  string `yaml:"part"`  // "body" | "header"
	Group int    `yaml:"group"` // capture group index
	Regex string `yaml:"regex"` // regex pattern
}

// ModelExtractor defines model list extraction.
type ModelExtractor struct {
	Part     string `yaml:"part"`                // "body"
	Type     string `yaml:"type"`                // "json_array" | "regex"
	JSONPath string `yaml:"json_path,omitempty"` // e.g. "models[*].name" or "data[*].id"
	Regex    string `yaml:"regex,omitempty"`      // regex alternative
	Group    int    `yaml:"group,omitempty"`      // capture group for regex
}

// AuthRule defines how to determine authentication status.
type AuthRule struct {
	Endpoint     string   `yaml:"endpoint"`                // which path to use for auth detection
	OpenStatus   []int    `yaml:"open_status"`             // status codes meaning no auth
	AuthStatus   []int    `yaml:"auth_status"`             // status codes meaning auth required
	AuthKeywords []string `yaml:"auth_keywords,omitempty"` // body keywords indicating auth required
}

// RiskMatrix maps auth status to risk severity.
type RiskMatrix struct {
	OpenWithModels string `yaml:"open_with_models"` // e.g. "critical"
	OpenNoModels   string `yaml:"open_no_models"`   // e.g. "high"
	AuthRequired   string `yaml:"auth_required"`    // e.g. "medium"
}

// EffectiveMethod returns the method to use (defaults to GET).
func (r *HTTPRule) EffectiveMethod() string {
	if r.Method == "" {
		return "GET"
	}
	return r.Method
}

// EffectivePriority returns the template priority (defaults to 50).
func (t *TemplateInfo) EffectivePriority() int {
	if t.Priority <= 0 {
		return 50
	}
	return t.Priority
}
