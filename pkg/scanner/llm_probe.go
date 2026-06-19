package scanner

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/llmtpl"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/netproxy"
)

// ProbeLLMWithHostname probes a single HTTP candidate for LLM inference APIs
// using the template engine. Returns nil if no framework matches.
func ProbeLLMWithHostname(ctx context.Context, engine *llmtpl.Engine, baseURL, hostname string, timeoutMs int) *models.LLMServer {
	if engine == nil {
		return nil
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout < 3*time.Second {
		timeout = 3 * time.Second
	}

	client := buildLLMHTTPClient(hostname, timeout)

	result := engine.ProbeTarget(ctx, baseURL, client)
	if result == nil {
		return nil
	}

	// Convert MatchResult → LLMServer
	llmModels := make([]models.LLMModel, 0, len(result.Models))
	for _, id := range result.Models {
		llmModels = append(llmModels, models.LLMModel{ID: id})
	}

	evidence := models.LLMEvidence{
		MatchedEndpoints: make([]models.LLMEndpointEvidence, 0, len(result.Evidence)),
	}
	var totalMs float64
	for _, ev := range result.Evidence {
		evidence.MatchedEndpoints = append(evidence.MatchedEndpoints, models.LLMEndpointEvidence{
			Method:     ev.Method,
			Path:       ev.Path,
			StatusCode: ev.StatusCode,
			Matched:    ev.Matched,
			ResponseMs: ev.ResponseMs,
		})
		if ev.ResponseMs > 0 {
			totalMs += ev.ResponseMs
		}
	}
	avgMs := float64(0)
	if len(result.Evidence) > 0 {
		avgMs = totalMs / float64(len(result.Evidence))
	}

	return &models.LLMServer{
		ServiceType:      "llm_inference_api",
		Framework:        result.TemplateName,
		FrameworkVersion: result.FrameworkVersion,
		Models:           llmModels,
		ModelCount:       len(llmModels),
		AuthStatus:       result.AuthStatus,
		RiskLevel:        result.RiskLevel,
		FingerprintScore: result.Score,
		TLSEnabled:       strings.HasPrefix(baseURL, "https"),
		ResponseTimeMs:   avgMs,
		Evidence:         evidence,
	}
}

func buildLLMHTTPClient(hostname string, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if hostname != "" {
		tlsCfg.ServerName = hostname
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: timeout,
		// Proxy support — consistent with MCP/A2A probes
		Proxy:       netproxy.HTTPProxy(),
		DialContext: netproxy.HTTPDialContext(timeout),
		// Connection pool tuning for concurrent stage1/stage2 requests
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     10 * time.Second,
		// Skip decompression — body is limited to 64KB anyway
		DisableCompression: true,
	}
	return &http.Client{
		Timeout:   timeout * 2,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
