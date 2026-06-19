package llmtpl

import (
	"encoding/json"
	"testing"
)

func TestJsonGet(t *testing.T) {
	// Ollama /api/tags response
	ollamaJSON := `{"models":[{"name":"llama3:latest","size":4661224676},{"name":"codellama:latest","size":3791730596}]}`
	var ollamaData interface{}
	json.Unmarshal([]byte(ollamaJSON), &ollamaData)

	// OpenAI /v1/models response
	openaiJSON := `{"object":"list","data":[{"id":"gpt-4","object":"model","owned_by":"vllm"},{"id":"llama-3-8b","object":"model","owned_by":"vllm"}]}`
	var openaiData interface{}
	json.Unmarshal([]byte(openaiJSON), &openaiData)

	tests := []struct {
		name   string
		data   interface{}
		path   string
		expect interface{}
		ok     bool
	}{
		// Simple field access
		{"simple field", ollamaData, "models", nil, true}, // returns the array
		// Wildcard array
		{"wildcard names", ollamaData, "models[*].name", nil, true},
		// Indexed access
		{"first model name", ollamaData, "models[0].name", "llama3:latest", true},
		{"second model name", ollamaData, "models[1].name", "codellama:latest", true},
		// OpenAI format
		{"openai data ids", openaiData, "data[*].id", nil, true},
		{"openai first id", openaiData, "data[0].id", "gpt-4", true},
		{"openai first owned_by", openaiData, "data[0].owned_by", "vllm", true},
		{"openai object", openaiData, "object", "list", true},
		// Non-existent paths
		{"missing field", ollamaData, "nonexistent", nil, false},
		{"out of bounds", ollamaData, "models[99].name", nil, false},
		{"wrong type", ollamaData, "models.name", nil, false}, // models is array, not object
	}

	for _, tt := range tests {
		val, ok := jsonGet(tt.data, tt.path)
		if ok != tt.ok {
			t.Errorf("%s: jsonGet(%q) ok = %v, want %v", tt.name, tt.path, ok, tt.ok)
			continue
		}
		if !ok {
			continue
		}
		if tt.expect != nil {
			str := valueToString(val)
			expectStr := tt.expect.(string)
			if str != expectStr {
				t.Errorf("%s: jsonGet(%q) = %q, want %q", tt.name, tt.path, str, expectStr)
			}
		}
	}
}

func TestJsonGetStringSlice(t *testing.T) {
	ollamaJSON := `{"models":[{"name":"llama3:latest"},{"name":"codellama:latest"},{"name":"phi3:latest"}]}`
	var data interface{}
	json.Unmarshal([]byte(ollamaJSON), &data)

	models, ok := jsonGetStringSlice(data, "models[*].name")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(models) != 3 {
		t.Fatalf("expected 3 models, got %d: %v", len(models), models)
	}
	expected := []string{"llama3:latest", "codellama:latest", "phi3:latest"}
	for i, m := range models {
		if m != expected[i] {
			t.Errorf("models[%d] = %q, want %q", i, m, expected[i])
		}
	}

	// OpenAI format
	openaiJSON := `{"object":"list","data":[{"id":"model-a","object":"model"},{"id":"model-b","object":"model"}]}`
	json.Unmarshal([]byte(openaiJSON), &data)

	ids, ok := jsonGetStringSlice(data, "data[*].id")
	if !ok {
		t.Fatal("expected ok=true for openai format")
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d: %v", len(ids), ids)
	}
	if ids[0] != "model-a" || ids[1] != "model-b" {
		t.Errorf("ids = %v", ids)
	}
}

func TestExtractVersion(t *testing.T) {
	responses := map[string]*ProbeResponse{
		"GET /api/version": NewProbeResponse(200, "", []byte(`{"version":"0.5.3"}`), 0),
	}

	rules := []VersionRule{
		{
			Method: "GET",
			Path:   "/api/version",
			Extractor: Extractor{
				Part:  "body",
				Group: 1,
				Regex: `"version":"([^"]+)"`,
			},
		},
	}

	version := ExtractVersion(rules, responses)
	if version != "0.5.3" {
		t.Errorf("ExtractVersion = %q, want %q", version, "0.5.3")
	}
}

func TestExtractVersionWithMatcher(t *testing.T) {
	responses := map[string]*ProbeResponse{
		"GET /version": NewProbeResponse(200, "Content-Type: application/json", []byte(`{"version":"0.8.1"}`), 0),
	}

	rules := []VersionRule{
		{
			Method:   "GET",
			Path:     "/version",
			Matchers: []string{`body="\"version\""`},
			Extractor: Extractor{
				Part:  "body",
				Group: 1,
				Regex: `"version":"([^"]+)"`,
			},
		},
	}

	version := ExtractVersion(rules, responses)
	if version != "0.8.1" {
		t.Errorf("ExtractVersion = %q, want %q", version, "0.8.1")
	}
}

func TestExtractModelsJSON(t *testing.T) {
	responses := map[string]*ProbeResponse{
		"GET /api/tags": NewProbeResponse(200, "", []byte(`{"models":[{"name":"llama3:latest"},{"name":"phi3:mini"}]}`), 0),
	}

	rules := []ModelRule{
		{
			Method: "GET",
			Path:   "/api/tags",
			Extractor: ModelExtractor{
				Part:     "body",
				Type:     "json_array",
				JSONPath: "models[*].name",
			},
		},
	}

	models := ExtractModels(rules, responses)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d: %v", len(models), models)
	}
	if models[0] != "llama3:latest" || models[1] != "phi3:mini" {
		t.Errorf("models = %v", models)
	}
}

func TestExtractModelsRegex(t *testing.T) {
	responses := map[string]*ProbeResponse{
		"GET /info": NewProbeResponse(200, "", []byte(`{"model_id":"meta-llama/Llama-3-8B","model_dtype":"float16"}`), 0),
	}

	rules := []ModelRule{
		{
			Method: "GET",
			Path:   "/info",
			Extractor: ModelExtractor{
				Part:  "body",
				Type:  "regex",
				Regex: `"model_id":"([^"]+)"`,
				Group: 1,
			},
		},
	}

	models := ExtractModels(rules, responses)
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d: %v", len(models), models)
	}
	if models[0] != "meta-llama/Llama-3-8B" {
		t.Errorf("model = %q", models[0])
	}
}

func TestExtractModelsOpenAIFormat(t *testing.T) {
	responses := map[string]*ProbeResponse{
		"GET /v1/models": NewProbeResponse(200, "", []byte(`{"object":"list","data":[{"id":"gpt-4","object":"model","owned_by":"vllm"},{"id":"llama-3-8b","object":"model","owned_by":"vllm"}]}`), 0),
	}

	rules := []ModelRule{
		{
			Method: "GET",
			Path:   "/v1/models",
			Extractor: ModelExtractor{
				Part:     "body",
				Type:     "json_array",
				JSONPath: "data[*].id",
			},
		},
	}

	models := ExtractModels(rules, responses)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d: %v", len(models), models)
	}
	if models[0] != "gpt-4" || models[1] != "llama-3-8b" {
		t.Errorf("models = %v", models)
	}
}
