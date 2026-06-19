package llmtpl

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func TestEngineOllamaDetection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Ollama is running"))
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"models":[{"name":"llama3:latest","size":4661224676},{"name":"phi3:mini","size":2318370816}]}`))
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":"0.5.3"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	templates, err := LoadTemplates("")
	if err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(templates)
	if err != nil {
		t.Fatal(err)
	}

	result := engine.ProbeTarget(context.Background(), srv.URL, testClient())
	if result == nil {
		t.Fatal("expected match, got nil")
	}

	if result.TemplateID != "ollama" {
		t.Errorf("TemplateID = %q, want %q", result.TemplateID, "ollama")
	}
	if result.FrameworkVersion != "0.5.3" {
		t.Errorf("FrameworkVersion = %q, want %q", result.FrameworkVersion, "0.5.3")
	}
	if len(result.Models) != 2 {
		t.Errorf("Models count = %d, want 2: %v", len(result.Models), result.Models)
	} else {
		if result.Models[0] != "llama3:latest" {
			t.Errorf("Models[0] = %q, want %q", result.Models[0], "llama3:latest")
		}
	}
	if result.AuthStatus != "open" {
		t.Errorf("AuthStatus = %q, want %q", result.AuthStatus, "open")
	}
	if result.Score <= 0 {
		t.Errorf("Score = %f, want > 0", result.Score)
	}
}

func TestEngineNoMatch(t *testing.T) {
	// Regular web server — no LLM signals
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Welcome to my website</body></html>"))
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	templates, err := LoadTemplates("")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(templates)
	if err != nil {
		t.Fatal(err)
	}

	result := engine.ProbeTarget(context.Background(), srv.URL, testClient())
	if result != nil {
		t.Errorf("expected nil, got match: %+v", result)
	}
}

func TestEngineAuthRequired(t *testing.T) {
	// Simulate an LLM server that requires auth on /api/tags
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Ollama is running"))
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	templates, err := LoadTemplates("")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(templates)
	if err != nil {
		t.Fatal(err)
	}

	result := engine.ProbeTarget(context.Background(), srv.URL, testClient())
	if result == nil {
		t.Fatal("expected match (Ollama detected via / body), got nil")
	}
	if result.TemplateID != "ollama" {
		t.Errorf("TemplateID = %q, want %q", result.TemplateID, "ollama")
	}
	if result.AuthStatus != "auth_required" {
		t.Errorf("AuthStatus = %q, want %q", result.AuthStatus, "auth_required")
	}
}

func TestEngineTemplateCount(t *testing.T) {
	templates, err := LoadTemplates("")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(templates)
	if err != nil {
		t.Fatal(err)
	}
	if engine.TemplateCount() < 1 {
		t.Error("expected at least 1 template")
	}
}

