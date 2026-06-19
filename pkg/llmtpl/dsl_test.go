package llmtpl

import (
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		input  string
		nToks  int
		errMsg string
	}{
		{`body="hello"`, 3, ""},
		{`body="hello" && header="uvicorn"`, 7, ""},
		{`body="a" || body="b"`, 7, ""},
		{`(body="a" && body="b") || header="c"`, 13, ""},
		{`body="unterminated`, 0, "unterminated string"},
		{`body=="exact"`, 3, ""},
		{`body!="nope"`, 3, ""},
		{`body~="regex.*"`, 3, ""},
		{`status="200"`, 3, ""},
	}

	for _, tt := range tests {
		tokens, err := tokenize(tt.input)
		if tt.errMsg != "" {
			if err == nil {
				t.Errorf("tokenize(%q): expected error containing %q, got nil", tt.input, tt.errMsg)
			}
			continue
		}
		if err != nil {
			t.Errorf("tokenize(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if len(tokens) != tt.nToks {
			t.Errorf("tokenize(%q): expected %d tokens, got %d: %v", tt.input, tt.nToks, len(tokens), tokens)
		}
	}
}

func TestCompileRule(t *testing.T) {
	tests := []struct {
		expr   string
		hasErr bool
	}{
		{`body="Ollama is running"`, false},
		{`body="\"models\"" && body="\"name\""`, false},
		{`header="uvicorn" && body="\"object\"" && body="\"data\""`, false},
		{`body="a" || body="b"`, false},
		{`(body="a" || body="b") && header="c"`, false},
		{`body~="version.*\d+"`, false},
		{``, true},                // empty
		{`body`, true},            // incomplete
		{`body=`, true},           // missing literal
		{`body="a" &&`, true},     // trailing operator
		{`unknown="x"`, true},     // unknown field
	}

	for _, tt := range tests {
		_, err := CompileRule(tt.expr)
		if tt.hasErr && err == nil {
			t.Errorf("CompileRule(%q): expected error, got nil", tt.expr)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("CompileRule(%q): unexpected error: %v", tt.expr, err)
		}
	}
}

func TestRuleEval(t *testing.T) {
	tests := []struct {
		expr   string
		cfg    MatchConfig
		expect bool
	}{
		// Basic body contains
		{
			expr:   `body="Ollama is running"`,
			cfg:    MatchConfig{Body: "Ollama is running"},
			expect: true,
		},
		{
			expr:   `body="Ollama is running"`,
			cfg:    MatchConfig{Body: "some other page"},
			expect: false,
		},
		// Case insensitive
		{
			expr:   `body="OLLAMA IS RUNNING"`,
			cfg:    MatchConfig{Body: "Ollama is running"},
			expect: true,
		},
		// Header contains
		{
			expr:   `header="uvicorn"`,
			cfg:    MatchConfig{Header: "Server: uvicorn\r\nContent-Type: application/json"},
			expect: true,
		},
		// AND logic
		{
			expr:   `body="\"models\"" && body="\"name\""`,
			cfg:    MatchConfig{Body: `{"models":[{"name":"llama3"}]}`},
			expect: true,
		},
		{
			expr:   `body="\"models\"" && body="\"name\""`,
			cfg:    MatchConfig{Body: `{"models":[]}`},
			expect: false, // has "models" but not "name"
		},
		// OR logic
		{
			expr:   `body="vllm" || body="sglang"`,
			cfg:    MatchConfig{Body: `owned_by: sglang`},
			expect: true,
		},
		{
			expr:   `body="vllm" || body="sglang"`,
			cfg:    MatchConfig{Body: `owned_by: fastchat`},
			expect: false,
		},
		// Parentheses
		{
			expr:   `(body="a" || body="b") && header="x"`,
			cfg:    MatchConfig{Body: "a", Header: "x"},
			expect: true,
		},
		{
			expr:   `(body="a" || body="b") && header="x"`,
			cfg:    MatchConfig{Body: "a", Header: "y"},
			expect: false,
		},
		// NOT contains
		{
			expr:   `body!="error"`,
			cfg:    MatchConfig{Body: "success"},
			expect: true,
		},
		{
			expr:   `body!="error"`,
			cfg:    MatchConfig{Body: "an error occurred"},
			expect: false,
		},
		// Exact match
		{
			expr:   `body=="{}"`,
			cfg:    MatchConfig{Body: "{}"},
			expect: true,
		},
		{
			expr:   `body=="{}"`,
			cfg:    MatchConfig{Body: `{"key": "value"}`},
			expect: false,
		},
		// Regex match
		{
			expr:   `body~="version.*\\d+\\.\\d+"`,
			cfg:    MatchConfig{Body: `{"version":"0.5.3"}`},
			expect: true,
		},
		{
			expr:   `body~="version.*\\d+\\.\\d+"`,
			cfg:    MatchConfig{Body: `no version here`},
			expect: false,
		},
		// Status field
		{
			expr:   `status="200"`,
			cfg:    MatchConfig{StatusCode: "200"},
			expect: true,
		},
		{
			expr:   `status="401"`,
			cfg:    MatchConfig{StatusCode: "200"},
			expect: false,
		},
		// Complex real-world expression
		{
			expr: `header="uvicorn" && body="\"object\"" && body="\"data\""`,
			cfg: MatchConfig{
				Header: "Server: uvicorn\r\nContent-Type: application/json",
				Body:   `{"object":"list","data":[{"id":"model-1"}]}`,
			},
			expect: true,
		},
		// AI-Infra-Guard style: body contains with JSON escapes
		{
			expr:   `body="\"owned_by\":\"vllm\"" || body="\"owned_by\": \"vllm\""`,
			cfg:    MatchConfig{Body: `{"id":"m1","owned_by":"vllm"}`},
			expect: true,
		},
		{
			expr:   `body="\"owned_by\":\"vllm\"" || body="\"owned_by\": \"vllm\""`,
			cfg:    MatchConfig{Body: `{"id":"m1","owned_by": "vllm"}`},
			expect: true,
		},
		{
			expr:   `body="\"owned_by\":\"vllm\"" || body="\"owned_by\": \"vllm\""`,
			cfg:    MatchConfig{Body: `{"id":"m1","owned_by":"sglang"}`},
			expect: false,
		},
		// Empty body match (used in stage2 for health endpoints)
		{
			expr:   `body=""`,
			cfg:    MatchConfig{Body: "anything"},
			expect: true, // "" is contained in everything
		},
	}

	for _, tt := range tests {
		rule, err := CompileRule(tt.expr)
		if err != nil {
			t.Fatalf("CompileRule(%q): %v", tt.expr, err)
		}
		got := rule.Eval(&tt.cfg)
		if got != tt.expect {
			t.Errorf("Eval(%q, %+v) = %v, want %v", tt.expr, tt.cfg, got, tt.expect)
		}
	}
}

func TestEvalExpr(t *testing.T) {
	cfg := &MatchConfig{Body: "hello world", Header: "Content-Type: text/html"}
	result, err := EvalExpr(`body="hello"`, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Error("expected true")
	}

	result, err = EvalExpr(`body="goodbye"`, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Error("expected false")
	}
}

func BenchmarkRuleEval(b *testing.B) {
	rule, _ := CompileRule(`header="uvicorn" && body="\"object\"" && body="\"data\""`)
	cfg := &MatchConfig{
		Header: "Server: uvicorn\r\nContent-Type: application/json",
		Body:   `{"object":"list","data":[{"id":"model-1","owned_by":"vllm"}]}`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Eval(cfg)
	}
}
