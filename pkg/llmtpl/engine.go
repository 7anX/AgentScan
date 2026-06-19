package llmtpl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Match Result ───────────────────────────────────────────────────────────

// MatchResult is the output of the engine for a single target.
type MatchResult struct {
	TemplateID       string          // info.name from the matched template
	TemplateName     string          // info.name (display)
	Severity         string          // info.severity
	FrameworkVersion string          // extracted version
	Models           []string        // extracted model IDs
	AuthStatus       string          // "open" | "auth_required" | "unknown"
	RiskLevel        string          // "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
	MatchedPaths     []string        // paths where matchers hit
	Score            float64         // match confidence (0.0 - 1.0)
	Evidence         []ProbeEvidence // per-endpoint evidence
}

// ProbeEvidence records proof from a single probed endpoint.
type ProbeEvidence struct {
	Method       string
	Path         string
	StatusCode   int
	ResponseMs   float64
	Matched      bool
}

// ─── Compiled Template ──────────────────────────────────────────────────────

type compiledRule struct {
	Method   string
	Path     string
	Data     string
	Matchers []*Rule // compiled DSL rules (OR relation)
}

// CompiledTemplate holds a template with all DSL expressions pre-compiled.
type CompiledTemplate struct {
	Raw       *Template
	Stage1    []compiledRule
	Stage2    []compiledRule
	Negatives []*Rule
}

// ─── Engine ─────────────────────────────────────────────────────────────────

// Engine orchestrates template-driven LLM framework detection.
type Engine struct {
	templates []*CompiledTemplate
}

// NewEngine creates an engine with the given templates.
// All DSL expressions are compiled at construction time.
func NewEngine(templates []*Template) (*Engine, error) {
	compiled := make([]*CompiledTemplate, 0, len(templates))
	for _, t := range templates {
		ct, err := compileTemplate(t)
		if err != nil {
			return nil, fmt.Errorf("compile template %q: %w", t.Info.Name, err)
		}
		compiled = append(compiled, ct)
	}
	return &Engine{templates: compiled}, nil
}

// ProbeTarget runs all templates against a single base URL and returns
// the best-matching framework result. Returns nil if no template matches.
func (e *Engine) ProbeTarget(ctx context.Context, baseURL string, client *http.Client) *MatchResult {
	if len(e.templates) == 0 {
		return nil
	}

	// Stage 1: Collect all unique requests across all templates
	stage1Requests := e.collectRequests(true)

	// Execute all stage1 requests concurrently
	responses := executeRequests(ctx, client, baseURL, stage1Requests)
	if len(responses) == 0 {
		return nil
	}

	// Evaluate each template against stage1 responses
	type candidate struct {
		ct           *CompiledTemplate
		matchedPaths []string
		score        float64
		evidence     []ProbeEvidence
	}
	var candidates []candidate

	for _, ct := range e.templates {
		matchedPaths, score, evidence := evaluateRules(ct.Stage1, responses)
		if score == 0 {
			continue // no stage1 signal
		}

		// Check negatives
		negativeHit := false
		for _, neg := range ct.Negatives {
			// Evaluate against all responses
			for _, resp := range responses {
				cfg := responseToMatchConfig(resp)
				if neg.Eval(cfg) {
					negativeHit = true
					break
				}
			}
			if negativeHit {
				break
			}
		}
		if negativeHit {
			continue
		}

		candidates = append(candidates, candidate{
			ct:           ct,
			matchedPaths: matchedPaths,
			score:        score,
			evidence:     evidence,
		})
	}

	if len(candidates) == 0 {
		return nil
	}

	// Stage 2: Execute stage2 probes for candidates that have them
	stage2Requests := make(map[string]httpRequest)
	for _, c := range candidates {
		for _, rule := range c.ct.Stage2 {
			key := ResponseKey(rule.Method, rule.Path)
			// Skip if already fetched in stage1
			if _, already := responses[key]; already {
				continue
			}
			if _, exists := stage2Requests[key]; !exists {
				stage2Requests[key] = httpRequest{
					Method: rule.Method,
					Path:   rule.Path,
					Body:   rule.Data,
				}
			}
		}
	}

	if len(stage2Requests) > 0 {
		stage2Responses := executeRequests(ctx, client, baseURL, stage2Requests)
		// Merge into responses
		for k, v := range stage2Responses {
			responses[k] = v
		}

		// Re-evaluate with stage2 data
		for i, c := range candidates {
			if len(c.ct.Stage2) == 0 {
				continue
			}
			matchedPaths2, score2, evidence2 := evaluateRules(c.ct.Stage2, responses)
			if score2 > 0 {
				candidates[i].matchedPaths = append(candidates[i].matchedPaths, matchedPaths2...)
				candidates[i].score = (candidates[i].score + score2) / 2.0 // blend scores
				candidates[i].evidence = append(candidates[i].evidence, evidence2...)
			}
		}
	}

	// Disambiguate: sort by priority (ascending), then by matched rules (descending), then by score
	sort.Slice(candidates, func(i, j int) bool {
		pi := candidates[i].ct.Raw.Info.EffectivePriority()
		pj := candidates[j].ct.Raw.Info.EffectivePriority()
		if pi != pj {
			return pi < pj
		}
		if len(candidates[i].matchedPaths) != len(candidates[j].matchedPaths) {
			return len(candidates[i].matchedPaths) > len(candidates[j].matchedPaths)
		}
		return candidates[i].score > candidates[j].score
	})

	winner := candidates[0]
	tpl := winner.ct.Raw

	// Extract version
	version := ExtractVersion(tpl.Version, responses)

	// Extract models
	models := ExtractModels(tpl.Models, responses)

	// Determine auth status
	authStatus := evaluateAuth(tpl.Auth, responses)

	// Determine risk level
	riskLevel := evaluateRisk(tpl.Risk, authStatus, len(models))

	return &MatchResult{
		TemplateID:       tpl.Info.Name,
		TemplateName:     tpl.Info.Name,
		Severity:         tpl.Info.Severity,
		FrameworkVersion: version,
		Models:           models,
		AuthStatus:       authStatus,
		RiskLevel:        riskLevel,
		MatchedPaths:     winner.matchedPaths,
		Score:            winner.score,
		Evidence:         winner.evidence,
	}
}

// ─── Internal ───────────────────────────────────────────────────────────────

type httpRequest struct {
	Method string
	Path   string
	Body   string
}

func (e *Engine) collectRequests(stage1Only bool) map[string]httpRequest {
	requests := make(map[string]httpRequest)
	for _, ct := range e.templates {
		rules := ct.Stage1
		if !stage1Only {
			rules = append(rules, ct.Stage2...)
		}
		for _, rule := range rules {
			key := ResponseKey(rule.Method, rule.Path)
			if _, exists := requests[key]; !exists {
				requests[key] = httpRequest{
					Method: rule.Method,
					Path:   rule.Path,
					Body:   rule.Data,
				}
			}
		}
	}
	return requests
}

func executeRequests(ctx context.Context, client *http.Client, baseURL string, requests map[string]httpRequest) map[string]*ProbeResponse {
	responses := make(map[string]*ProbeResponse, len(requests))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for key, req := range requests {
		wg.Add(1)
		go func(k string, r httpRequest) {
			defer wg.Done()
			defer func() {
				if rv := recover(); rv != nil {
					// Swallow panic — treat as failed request
				}
			}()

			resp := doRequest(ctx, client, baseURL, r)
			if resp != nil {
				mu.Lock()
				responses[k] = resp
				mu.Unlock()
			}
		}(key, req)
	}

	wg.Wait()
	return responses
}

func doRequest(ctx context.Context, client *http.Client, baseURL string, req httpRequest) *ProbeResponse {
	url := strings.TrimRight(baseURL, "/") + req.Path

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "*/*")
	if req.Body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := time.Since(start)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read body with 64KB limit
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	// Build raw header string
	var headerBuf strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			headerBuf.WriteString(k)
			headerBuf.WriteString(": ")
			headerBuf.WriteString(v)
			headerBuf.WriteString("\r\n")
		}
	}

	return &ProbeResponse{
		StatusCode: resp.StatusCode,
		HeaderRaw:  headerBuf.String(),
		Body:       bodyBytes,
		BodyStr:    string(bodyBytes),
		ElapsedMs:  float64(elapsed.Milliseconds()),
	}
}

func evaluateRules(rules []compiledRule, responses map[string]*ProbeResponse) (matchedPaths []string, score float64, evidence []ProbeEvidence) {
	if len(rules) == 0 {
		return nil, 0, nil
	}

	matched := 0
	for _, rule := range rules {
		key := ResponseKey(rule.Method, rule.Path)
		resp, ok := responses[key]

		ev := ProbeEvidence{
			Method: rule.Method,
			Path:   rule.Path,
		}

		if !ok || resp == nil {
			evidence = append(evidence, ev)
			continue
		}

		ev.StatusCode = resp.StatusCode
		ev.ResponseMs = resp.ElapsedMs

		cfg := responseToMatchConfig(resp)

		// Matchers have OR semantics: any match → rule hit
		ruleMatched := false
		for _, m := range rule.Matchers {
			if m.Eval(cfg) {
				ruleMatched = true
				break
			}
		}

		ev.Matched = ruleMatched
		evidence = append(evidence, ev)

		if ruleMatched {
			matched++
			matchedPaths = append(matchedPaths, rule.Path)
		}
	}

	score = float64(matched) / float64(len(rules))
	return matchedPaths, score, evidence
}

func evaluateAuth(auth *AuthRule, responses map[string]*ProbeResponse) string {
	if auth == nil {
		return "unknown"
	}

	key := ResponseKey("GET", auth.Endpoint)
	resp, ok := responses[key]
	if !ok || resp == nil {
		return "unknown"
	}

	// Check open status
	for _, s := range auth.OpenStatus {
		if resp.StatusCode == s {
			return "open"
		}
	}

	// Check auth status
	for _, s := range auth.AuthStatus {
		if resp.StatusCode == s {
			return "auth_required"
		}
	}

	// Check auth keywords in body
	if len(auth.AuthKeywords) > 0 {
		bodyLower := strings.ToLower(string(resp.Body))
		for _, kw := range auth.AuthKeywords {
			if strings.Contains(bodyLower, strings.ToLower(kw)) {
				return "auth_required"
			}
		}
	}

	return "unknown"
}

func evaluateRisk(risk *RiskMatrix, authStatus string, modelCount int) string {
	if risk == nil {
		// Default risk mapping
		switch authStatus {
		case "open":
			if modelCount > 0 {
				return "CRITICAL"
			}
			return "HIGH"
		case "auth_required":
			return "MEDIUM"
		default:
			return "INFO"
		}
	}

	switch authStatus {
	case "open":
		if modelCount > 0 {
			return normalizeRisk(risk.OpenWithModels)
		}
		return normalizeRisk(risk.OpenNoModels)
	case "auth_required":
		return normalizeRisk(risk.AuthRequired)
	default:
		return "INFO"
	}
}

func normalizeRisk(r string) string {
	switch strings.ToLower(r) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "info":
		return "INFO"
	default:
		return "INFO"
	}
}

func compileTemplate(t *Template) (*CompiledTemplate, error) {
	ct := &CompiledTemplate{Raw: t}

	// Compile stage1
	for _, rule := range t.HTTP {
		cr, err := compileHTTPRule(rule)
		if err != nil {
			return nil, fmt.Errorf("http rule %s: %w", rule.Path, err)
		}
		ct.Stage1 = append(ct.Stage1, cr)
	}

	// Compile stage2
	for _, rule := range t.Stage2 {
		cr, err := compileHTTPRule(rule)
		if err != nil {
			return nil, fmt.Errorf("stage2 rule %s: %w", rule.Path, err)
		}
		ct.Stage2 = append(ct.Stage2, cr)
	}

	// Compile negatives
	for _, neg := range t.Negatives {
		r, err := CompileRule(neg)
		if err != nil {
			return nil, fmt.Errorf("negative %q: %w", neg, err)
		}
		ct.Negatives = append(ct.Negatives, r)
	}

	return ct, nil
}

func compileHTTPRule(rule HTTPRule) (compiledRule, error) {
	cr := compiledRule{
		Method: rule.EffectiveMethod(),
		Path:   rule.Path,
		Data:   rule.Data,
	}

	for _, m := range rule.Matchers {
		compiled, err := CompileRule(m)
		if err != nil {
			return cr, err
		}
		cr.Matchers = append(cr.Matchers, compiled)
	}

	return cr, nil
}

// TemplateCount returns how many templates are loaded.
func (e *Engine) TemplateCount() int {
	return len(e.templates)
}

// TemplateNames returns all loaded template names.
func (e *Engine) TemplateNames() []string {
	names := make([]string, len(e.templates))
	for i, ct := range e.templates {
		names[i] = ct.Raw.Info.Name
	}
	return names
}

// unused but kept for API completeness
var _ = strconv.Itoa
