package llmtpl

import (
	"testing"
)

func TestLoadTemplatesEmbedded(t *testing.T) {
	templates, err := LoadTemplates("")
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if len(templates) < 25 {
		t.Fatalf("expected at least 25 embedded templates, got %d", len(templates))
	}

	// Check the ollama template loaded correctly
	var ollama *Template
	for _, tpl := range templates {
		if tpl.Info.Name == "ollama" {
			ollama = tpl
			break
		}
	}
	if ollama == nil {
		t.Fatal("ollama template not found")
	}
	if ollama.Info.Priority != 1 {
		t.Errorf("ollama priority = %d, want 1", ollama.Info.Priority)
	}
	if ollama.Info.Severity != "critical" {
		t.Errorf("ollama severity = %q, want %q", ollama.Info.Severity, "critical")
	}
	if len(ollama.HTTP) != 2 {
		t.Errorf("ollama http rules = %d, want 2", len(ollama.HTTP))
	}
	if len(ollama.Stage2) != 1 {
		t.Errorf("ollama stage2 rules = %d, want 1", len(ollama.Stage2))
	}
	if ollama.Auth == nil {
		t.Error("ollama auth is nil")
	} else if ollama.Auth.Endpoint != "/api/tags" {
		t.Errorf("ollama auth.endpoint = %q, want %q", ollama.Auth.Endpoint, "/api/tags")
	}
	if ollama.Risk == nil {
		t.Error("ollama risk is nil")
	} else if ollama.Risk.OpenWithModels != "critical" {
		t.Errorf("ollama risk.open_with_models = %q, want %q", ollama.Risk.OpenWithModels, "critical")
	}
}

func TestParseTemplate(t *testing.T) {
	yaml := `
info:
  name: test-framework
  severity: high
  priority: 42
http:
  - method: GET
    path: '/test'
    matchers:
      - body="test-marker"
version:
  - method: GET
    path: '/version'
    extractor:
      part: body
      group: 1
      regex: '"version":"([^"]+)"'
models:
  - method: GET
    path: '/v1/models'
    extractor:
      part: body
      type: json_array
      json_path: 'data[*].id'
auth:
  endpoint: '/v1/models'
  open_status: [200]
  auth_status: [401, 403]
risk:
  open_with_models: high
  open_no_models: medium
  auth_required: info
negatives:
  - body="other-framework"
`
	tpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if tpl.Info.Name != "test-framework" {
		t.Errorf("name = %q", tpl.Info.Name)
	}
	if tpl.Info.EffectivePriority() != 42 {
		t.Errorf("priority = %d", tpl.Info.EffectivePriority())
	}
	if len(tpl.HTTP) != 1 {
		t.Errorf("http rules = %d", len(tpl.HTTP))
	}
	if len(tpl.Version) != 1 {
		t.Errorf("version rules = %d", len(tpl.Version))
	}
	if len(tpl.Models) != 1 {
		t.Errorf("models rules = %d", len(tpl.Models))
	}
	if tpl.Models[0].Extractor.JSONPath != "data[*].id" {
		t.Errorf("models json_path = %q", tpl.Models[0].Extractor.JSONPath)
	}
	if len(tpl.Negatives) != 1 {
		t.Errorf("negatives = %d", len(tpl.Negatives))
	}
}

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name   string
		tpl    Template
		hasErr bool
	}{
		{
			name: "valid minimal",
			tpl: Template{
				Info: TemplateInfo{Name: "test"},
				HTTP: []HTTPRule{{Path: "/", Matchers: []string{`body="x"`}}},
			},
			hasErr: false,
		},
		{
			name:   "missing name",
			tpl:    Template{HTTP: []HTTPRule{{Path: "/", Matchers: []string{`body="x"`}}}},
			hasErr: true,
		},
		{
			name:   "no http rules",
			tpl:    Template{Info: TemplateInfo{Name: "test"}},
			hasErr: true,
		},
		{
			name: "invalid matcher DSL",
			tpl: Template{
				Info: TemplateInfo{Name: "test"},
				HTTP: []HTTPRule{{Path: "/", Matchers: []string{`invalid syntax`}}},
			},
			hasErr: true,
		},
		{
			name: "invalid negative DSL",
			tpl: Template{
				Info:      TemplateInfo{Name: "test"},
				HTTP:      []HTTPRule{{Path: "/", Matchers: []string{`body="x"`}}},
				Negatives: []string{`broken!!`},
			},
			hasErr: true,
		},
	}

	for _, tt := range tests {
		err := ValidateTemplate(&tt.tpl)
		if tt.hasErr && err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tt.name, err)
		}
	}
}

func TestEffectiveMethod(t *testing.T) {
	r := HTTPRule{Path: "/test"}
	if r.EffectiveMethod() != "GET" {
		t.Errorf("empty method should default to GET, got %q", r.EffectiveMethod())
	}
	r.Method = "POST"
	if r.EffectiveMethod() != "POST" {
		t.Errorf("method should be POST, got %q", r.EffectiveMethod())
	}
}

func TestEffectivePriority(t *testing.T) {
	info := TemplateInfo{Name: "test"}
	if info.EffectivePriority() != 50 {
		t.Errorf("default priority should be 50, got %d", info.EffectivePriority())
	}
	info.Priority = 10
	if info.EffectivePriority() != 10 {
		t.Errorf("priority should be 10, got %d", info.EffectivePriority())
	}
}
