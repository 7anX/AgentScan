package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/models"
)

const (
	a2aConfirmedThreshold = 0.65
	a2aProbableThreshold  = 0.45
)

type A2AProbeResult struct {
	CardPath         string
	CardURL          string
	Profile          models.A2AProfile
	ExposureStatus   models.A2AExposureStatus
	ExposureSignals  []string
	A2AConfirmed     bool
	FingerprintScore float64
	Signals          []string
	Negatives        []string
	AgentName        string
	Description      string
	Version          string
	ProtocolVersion  string
	Provider         map[string]interface{}
	Capabilities     models.A2ACapabilities
	Skills           []models.A2ASkill
	Interfaces       []models.A2AInterface
	NoAuth           bool
	AuthRequired     bool
	EndpointDisabled bool
	RawCard          json.RawMessage
	Evidence         models.A2AEvidence
	ResponseTimeMs   float64
}

type a2aCardScore struct {
	score     float64
	signals   []string
	negatives []string
	profile   models.A2AProfile
	confirmed bool
}

// ProbeA2AWithHostname 探测 A2A Agent Card
// dict 为字典集合；传 nil 时使用 config.DefaultDictSet()。
func ProbeA2AWithHostname(ctx context.Context, baseURL, hostname, urlPath string, timeoutMs int, includeProbable bool, dict *config.DictSet) *A2AProbeResult {
	if dict == nil {
		dict = config.DefaultDictSet()
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	var best *A2AProbeResult
	for _, cardPath := range buildA2ACardPaths(urlPath, dict) {
		cardURL := baseURL + cardPath
		start := time.Now()
		data, raw, statusCode, contentType, headers, err := fetchA2ACard(ctx, client, cardURL)
		elapsed := float64(time.Since(start).Milliseconds())
		if err != nil || data == nil {
			continue
		}

		score := scoreA2ACard(cardPath, contentType, headers, data)
		if len(score.negatives) > 0 {
			continue
		}
		if !score.confirmed && !(includeProbable && score.score >= a2aProbableThreshold) {
			continue
		}

		profile := score.profile
		if !score.confirmed {
			profile = models.A2AProfileProbable
		}

		result := &A2AProbeResult{
			CardPath:         cardPath,
			CardURL:          cardURL,
			Profile:          profile,
			ExposureStatus:   exposureStatusForCard(profile),
			A2AConfirmed:     score.confirmed,
			FingerprintScore: score.score,
			Signals:          score.signals,
			Negatives:        score.negatives,
			AgentName:        stringField(data, "name"),
			Description:      stringField(data, "description"),
			Version:          stringField(data, "version"),
			ProtocolVersion:  firstNonEmptyString(stringField(data, "protocolVersion"), stringField(data, "schemaVersion"), stringField(data, "schema_version")),
			Provider:         mapField(data, "provider"),
			Capabilities:     extractA2ACapabilities(data),
			Skills:           extractA2ASkills(data),
			RawCard:          raw,
			ResponseTimeMs:   elapsed,
			Evidence: models.A2AEvidence{
				Card: models.A2ACardEvidence{
					URL:             cardURL,
					StatusCode:      statusCode,
					ContentType:     contentType,
					ResponseHeaders: headers,
				},
				Fingerprint: models.A2AFingerprintEvidence{
					Score:     score.score,
					Profile:   profile,
					Signals:   score.signals,
					Negatives: score.negatives,
				},
			},
		}

		result.Interfaces = extractA2AInterfaces(baseURL, cardURL, data)
		probeReasons := probeA2AInterfaces(ctx, client, result)
		var extendedSignals []string
		if boolLike(result.Capabilities.ExtendedAgentCard) {
			extendedSignals = probeExtendedCard(ctx, client, result)
		}
		result.ExposureSignals = extractA2AExposureSignals(result, extendedSignals)
		result.Evidence.Auth = a2aAuthEvidence(result, detectDeclaredAuth(data), probeReasons)

		if result.A2AConfirmed {
			return result
		}
		if best == nil || result.FingerprintScore > best.FingerprintScore {
			best = result
		}
	}
	return best
}

func buildA2ACardPaths(urlPath string, dict *config.DictSet) []string {
	if dict == nil {
		dict = config.DefaultDictSet()
	}
	seen := map[string]struct{}{}
	var paths []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}

	normalized := normalizeProbeEndpoint(urlPath)
	if normalized != "" && normalized != "/" {
		lower := strings.ToLower(normalized)
		if strings.HasSuffix(lower, ".json") || strings.Contains(lower, "agent-card") || strings.HasSuffix(lower, "agent.json") {
			add(normalized)
		} else {
			prefix := strings.TrimRight(normalized, "/")
			for _, base := range dict.A2ACardPaths {
				add(prefix + base)
			}
		}
	}
	for _, base := range dict.A2ACardPaths {
		add(base)
	}
	return paths
}

func fetchA2ACard(ctx context.Context, client *http.Client, cardURL string) (map[string]interface{}, json.RawMessage, int, string, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cardURL, nil)
	if err != nil {
		return nil, nil, 0, "", nil, err
	}
	req.Header.Set("Accept", "application/a2a+json, application/json")
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, "", nil, err
	}
	defer resp.Body.Close()

	headers := relevantA2AHeaders(resp.Header)
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		return nil, nil, resp.StatusCode, resp.Header.Get("Content-Type"), headers, fmt.Errorf("status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, resp.StatusCode, resp.Header.Get("Content-Type"), headers, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, raw, resp.StatusCode, resp.Header.Get("Content-Type"), headers, err
	}
	return data, raw, resp.StatusCode, resp.Header.Get("Content-Type"), headers, nil
}

func scoreA2ACard(cardPath, contentType string, headers map[string]string, data map[string]interface{}) a2aCardScore {
	var s a2aCardScore
	add := func(points float64, signal string) {
		s.score += points
		s.signals = append(s.signals, signal)
	}

	if strings.Contains(strings.ToLower(contentType), "application/a2a+json") {
		add(0.10, "content_type_a2a_json")
	}
	if headers["A2A-Version"] != "" {
		add(0.20, "a2a_version_header")
	}
	if stringField(data, "name") != "" {
		add(0.10, "name")
	}
	if stringField(data, "description") != "" {
		add(0.10, "description")
	}
	if _, ok := data["capabilities"].(map[string]interface{}); ok {
		add(0.15, "capabilities")
	}
	if _, ok := data["skills"].([]interface{}); ok {
		add(0.20, "skills")
	}
	if _, ok := data["supportedInterfaces"].([]interface{}); ok {
		add(0.20, "supported_interfaces")
	}
	if data["securitySchemes"] != nil || data["security"] != nil {
		add(0.10, "security")
	}
	if stringField(data, "protocolVersion") != "" {
		add(0.10, "protocol_version")
	}
	if strings.EqualFold(stringField(data, "protocol"), "A2A") {
		add(0.25, "protocol_a2a")
	}
	if stringField(data, "schemaVersion") != "" || stringField(data, "schema_version") != "" {
		add(0.05, "schema_version")
	}
	if stringField(data, "url") != "" {
		add(0.10, "url")
	}
	if data["authentication"] != nil {
		add(0.10, "authentication")
	}
	if data["defaultInputModes"] != nil || data["defaultOutputModes"] != nil {
		add(0.10, "default_modes")
	}
	if _, ok := data["supportsAuthenticatedExtendedCard"]; ok {
		add(0.10, "extended_card_flag")
	}
	if hasA2ACapabilityKey(data) {
		add(0.10, "a2a_capability")
	}
	if hasA2ABinding(data) {
		add(0.15, "binding")
	}

	s.negatives = a2aNegativeSignals(data)
	if len(s.negatives) > 0 {
		return s
	}

	if strings.HasSuffix(cardPath, "/agent-card.json") && s.score >= a2aConfirmedThreshold {
		s.profile = models.A2AProfileAgentCard
		s.confirmed = true
		return s
	}
	if strings.HasSuffix(cardPath, "/agent.json") && s.score >= a2aConfirmedThreshold {
		s.profile = models.A2AProfileLegacyAgentJSON
		s.confirmed = true
		return s
	}
	if s.score >= a2aProbableThreshold {
		s.profile = models.A2AProfileProbable
	}
	return s
}

func hasA2ACapabilityKey(data map[string]interface{}) bool {
	caps, ok := data["capabilities"].(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"streaming", "pushNotifications", "extendedAgentCard", "extensions", "stateTransitionHistory"} {
		if _, ok := caps[key]; ok {
			return true
		}
	}
	return false
}

func hasA2ABinding(data map[string]interface{}) bool {
	items, ok := data["supportedInterfaces"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		binding := strings.ToUpper(stringField(m, "protocolBinding"))
		if binding == "JSONRPC" || binding == "HTTP+JSON" || binding == "GRPC" {
			return true
		}
	}
	return false
}

func a2aNegativeSignals(data map[string]interface{}) []string {
	var out []string
	schema := strings.ToLower(firstNonEmptyString(stringField(data, "$schema"), stringField(data, "schema")))
	if strings.Contains(schema, "agentprotocol.ai/schema/agent.json") {
		out = append(out, "agent_protocol_like")
	}
	if strings.Contains(schema, "amp.agent-discovery") {
		out = append(out, "amp_agent_discovery_like")
	}
	if data["openapi"] != nil || data["swagger"] != nil {
		out = append(out, "openapi_like")
	}
	if data["api"] != nil && data["auth"] != nil && data["schema_version"] != nil {
		out = append(out, "chatgpt_plugin_like")
	}
	if caps, ok := data["capabilities"].(map[string]interface{}); ok && caps["actions"] != nil {
		if _, hasSkills := data["skills"].([]interface{}); !hasSkills {
			out = append(out, "generic_actions_card")
		}
	}
	sort.Strings(out)
	return out
}

func extractA2ACapabilities(data map[string]interface{}) models.A2ACapabilities {
	caps, _ := data["capabilities"].(map[string]interface{})
	if caps == nil {
		return models.A2ACapabilities{}
	}
	return models.A2ACapabilities{
		Streaming:              caps["streaming"],
		PushNotifications:      caps["pushNotifications"],
		StateTransitionHistory: caps["stateTransitionHistory"],
		ExtendedAgentCard:      firstNonNil(caps["extendedAgentCard"], data["supportsAuthenticatedExtendedCard"]),
		Extensions:             caps["extensions"],
		Raw:                    caps,
	}
}

func extractA2ASkills(data map[string]interface{}) []models.A2ASkill {
	raw, ok := data["skills"].([]interface{})
	if !ok {
		return nil
	}
	skills := make([]models.A2ASkill, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		skill := models.A2ASkill{
			ID:          stringField(m, "id"),
			Name:        stringField(m, "name"),
			Description: stringField(m, "description"),
			Tags:        stringSliceField(m, "tags"),
			InputModes:  stringSliceField(m, "inputModes"),
			OutputModes: stringSliceField(m, "outputModes"),
		}
		if skill.ID != "" || skill.Name != "" {
			skills = append(skills, skill)
		}
	}
	return skills
}

func extractA2AInterfaces(baseURL, cardURL string, data map[string]interface{}) []models.A2AInterface {
	var out []models.A2AInterface
	add := func(rawURL, source, binding, version string) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			return
		}
		resolved, crossHost, privateAdvertised, ok := resolveA2AInterfaceURL(baseURL, cardURL, rawURL)
		if !ok {
			return
		}
		if binding == "" {
			binding = inferA2ABinding(resolved)
		}
		out = append(out, models.A2AInterface{
			URL:                   resolved,
			AdvertisedURL:         rawURL,
			Source:                source,
			Binding:               binding,
			ProtocolVersion:       version,
			CrossHost:             crossHost,
			PrivateHostAdvertised: privateAdvertised,
			Status:                models.A2AStatusUnknown,
		})
	}

	if items, ok := data["supportedInterfaces"].([]interface{}); ok {
		for _, item := range items {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			add(firstNonEmptyString(stringField(m, "url"), stringField(m, "endpoint")), "supportedInterfaces", strings.ToUpper(stringField(m, "protocolBinding")), stringField(m, "version"))
		}
	}
	add(stringField(data, "url"), "url", "", stringField(data, "protocolVersion"))
	extractEndpointInterfaces(data, add)

	if !hasA2APathInterface(out) {
		add("/a2a", "inferred", "unknown-jsonrpc-candidate", stringField(data, "protocolVersion"))
	}

	return dedupeA2AInterfaces(out)
}

func extractEndpointInterfaces(data map[string]interface{}, add func(rawURL, source, binding, version string)) {
	switch endpoints := data["endpoints"].(type) {
	case []interface{}:
		for _, item := range endpoints {
			switch v := item.(type) {
			case string:
				add(v, "endpoints", "", "")
			case map[string]interface{}:
				add(firstNonEmptyString(stringField(v, "url"), stringField(v, "endpoint")), "endpoints", strings.ToUpper(stringField(v, "protocolBinding")), stringField(v, "version"))
			}
		}
	case map[string]interface{}:
		for _, item := range endpoints {
			switch v := item.(type) {
			case string:
				add(v, "endpoints", "", "")
			case map[string]interface{}:
				add(firstNonEmptyString(stringField(v, "url"), stringField(v, "endpoint")), "endpoints", strings.ToUpper(stringField(v, "protocolBinding")), stringField(v, "version"))
			}
		}
	}
}

func resolveA2AInterfaceURL(baseURL, cardURL, rawURL string) (string, bool, bool, bool) {
	cardParsed, err := url.Parse(cardURL)
	if err != nil {
		return "", false, false, false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", false, false, false
	}
	resolved := cardParsed.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false, false, false
	}
	if strings.Contains(resolved.EscapedPath(), "..") {
		return "", false, false, false
	}
	crossHost := !strings.EqualFold(resolved.Host, cardParsed.Host)
	privateAdvertised := isPrivateA2AHost(resolved.Hostname())
	if privateAdvertised && looksA2AEndpointPath(resolved.Path) {
		baseParsed, err := url.Parse(baseURL)
		if err != nil {
			return "", false, false, false
		}
		rebased := *baseParsed
		rebased.Path = resolved.Path
		rebased.RawQuery = resolved.RawQuery
		return rebased.String(), true, true, true
	}
	return resolved.String(), crossHost, privateAdvertised, true
}

func inferA2ABinding(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	path := strings.ToLower(u.Path)
	if strings.Contains(path, "/a2a") || strings.Contains(path, "/rpc") || strings.Contains(path, "/jsonrpc") {
		return "unknown-jsonrpc-candidate"
	}
	return "unknown"
}

func hasA2APathInterface(items []models.A2AInterface) bool {
	for _, item := range items {
		if looksA2AEndpointPath(mustURLPath(item.URL)) {
			return true
		}
	}
	return false
}

func dedupeA2AInterfaces(items []models.A2AInterface) []models.A2AInterface {
	seen := make(map[string]struct{}, len(items))
	out := make([]models.A2AInterface, 0, len(items))
	for _, item := range items {
		if item.URL == "" {
			continue
		}
		if _, ok := seen[item.URL]; ok {
			continue
		}
		seen[item.URL] = struct{}{}
		out = append(out, item)
	}
	return out
}

func probeA2AInterfaces(ctx context.Context, client *http.Client, result *A2AProbeResult) []string {
	statusReasons := []string{"card fetched and parsed"}
	for i := range result.Interfaces {
		if !shouldProbeA2AJSONRPC(result.Interfaces[i]) {
			continue
		}
		probeA2AJSONRPCInterface(ctx, client, &result.Interfaces[i], result.ProtocolVersion)
		switch result.Interfaces[i].Status {
		case models.A2AStatusNoAuthJSONRPCReachable, models.A2AStatusNoAuthStructuredRPCError:
			result.NoAuth = true
			result.ExposureStatus = models.A2AExposureJSONRPCNoAuth
			statusReasons = append(statusReasons, "JSON-RPC unknown-method probe returned without auth")
		case models.A2AStatusAuthRequired:
			result.AuthRequired = true
			if result.ExposureStatus != models.A2AExposureJSONRPCNoAuth {
				result.ExposureStatus = models.A2AExposureAuthRequired
			}
			statusReasons = append(statusReasons, "interface returned auth challenge")
		case models.A2AStatusEndpointDisabled:
			result.EndpointDisabled = true
			if result.ExposureStatus != models.A2AExposureJSONRPCNoAuth && !result.AuthRequired {
				result.ExposureStatus = models.A2AExposureDisabled
			}
			statusReasons = append(statusReasons, "interface reported disabled/not configured")
		}
	}
	if result.ExposureStatus == "" {
		result.ExposureStatus = exposureStatusForCard(result.Profile)
	}
	return statusReasons
}

func shouldProbeA2AJSONRPC(item models.A2AInterface) bool {
	binding := strings.ToUpper(item.Binding)
	return binding == "JSONRPC" || strings.EqualFold(item.Binding, "unknown-jsonrpc-candidate")
}

func probeA2AJSONRPCInterface(ctx context.Context, client *http.Client, item *models.A2AInterface, version string) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tasks/get",
		"params":  map[string]interface{}{},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", item.URL, bytes.NewReader(body))
	if err != nil {
		item.Status = models.A2AStatusNetworkError
		item.ErrorMessage = err.Error()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("A2A-Version", firstNonEmptyString(item.ProtocolVersion, version, "1.0"))
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		item.Status = models.A2AStatusNetworkError
		item.ErrorMessage = err.Error()
		return
	}
	defer resp.Body.Close()

	item.HTTPStatus = resp.StatusCode
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.Header.Get("WWW-Authenticate") != "" {
		item.Status = models.A2AStatusAuthRequired
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		if resp.StatusCode == http.StatusMethodNotAllowed {
			item.Status = models.A2AStatusMethodNotAllowedNonRPC
		} else {
			item.Status = models.A2AStatusUnknown
		}
		return
	}
	errMap, _ := data["error"].(map[string]interface{})
	if code, ok := errMap["code"]; ok {
		item.ErrorCode = fmt.Sprint(code)
	}
	item.ErrorMessage, _ = errMap["message"].(string)

	msg := strings.ToLower(item.ErrorMessage)
	if strings.Contains(msg, "endpoint is disabled") || strings.Contains(msg, "not configured") ||
		strings.Contains(msg, "maintenance") || strings.Contains(msg, "placeholder") {
		item.Status = models.A2AStatusEndpointDisabled
		return
	}
	if data["jsonrpc"] == "2.0" && item.ErrorCode == "-32601" {
		item.Status = models.A2AStatusNoAuthJSONRPCReachable
		return
	}
	if data["jsonrpc"] == "2.0" {
		item.Status = models.A2AStatusNoAuthStructuredRPCError
		return
	}
	item.Status = models.A2AStatusUnknown
}

func extractA2AExposureSignals(result *A2AProbeResult, extra []string) []string {
	set := map[string]struct{}{}
	add := func(signal string) {
		if signal != "" {
			set[signal] = struct{}{}
		}
	}
	// Include any extra signals (e.g. from extended card probe)
	for _, s := range extra {
		add(s)
	}
	if result.Profile == models.A2AProfileLegacyAgentJSON {
		add("legacy_agent_json_public")
	}
	if result.Profile == models.A2AProfileAgentCard {
		add("official_agent_card")
	}
	if boolLike(result.Capabilities.PushNotifications) {
		add("push_notifications_true")
	}
	if !strings.HasPrefix(result.CardURL, "https://") {
		add("http_plaintext_card")
	}
	for _, iface := range result.Interfaces {
		if iface.PrivateHostAdvertised {
			add("private_host_advertised")
		}
		if iface.CrossHost {
			add("cross_host_interface_url")
		}
		if iface.AdvertisedURL != "" && strings.HasPrefix(iface.AdvertisedURL, "/") {
			add("relative_a2a_endpoint")
		}
		if iface.Status == models.A2AStatusNoAuthJSONRPCReachable {
			add("no_auth_jsonrpc_method_not_found")
		}
		if iface.Status == models.A2AStatusEndpointDisabled {
			add("a2a_endpoint_disabled")
		}
	}
	if hasSystemAdminSkill(result.Skills) {
		add("system_admin_skill_names")
	}
	out := make([]string, 0, len(set))
	for signal := range set {
		out = append(out, signal)
	}
	sort.Strings(out)
	return out
}

func a2aAuthEvidence(result *A2AProbeResult, declaredAuth string, probeReasons []string) models.A2AAuthEvidence {
	status := string(result.ExposureStatus)
	reasons := append([]string(nil), probeReasons...) // copy, don't mutate caller's slice
	if len(reasons) == 0 {
		reasons = append(reasons, "public card fetched; callable interface not verified")
	}
	return models.A2AAuthEvidence{Declared: declaredAuth, Status: status, Reasons: reasons}
}

func exposureStatusForCard(profile models.A2AProfile) models.A2AExposureStatus {
	switch profile {
	case models.A2AProfileProbable:
		return models.A2AExposureProbable
	default:
		return models.A2AExposureCardPublic
	}
}

// detectDeclaredAuth examines securitySchemes/security fields from the Agent Card.
// Returns "declared_none", "declared_required", or "declared_ambiguous".
func detectDeclaredAuth(data map[string]interface{}) string {
	hasSchemes := data["securitySchemes"] != nil
	hasSecurity := data["security"] != nil
	hasAuthentication := data["authentication"] != nil
	if !hasSchemes && !hasSecurity && !hasAuthentication {
		return "declared_none"
	}
	// security field present and non-empty = requirements declared
	switch sec := data["security"].(type) {
	case []interface{}:
		if len(sec) > 0 {
			return "declared_required"
		}
	case map[string]interface{}:
		if len(sec) > 0 {
			return "declared_required"
		}
	}
	if hasSchemes || hasAuthentication {
		return "declared_ambiguous"
	}
	return "declared_ambiguous"
}

// probeExtendedCard fires GetExtendedAgentCard via JSON-RPC when the card advertises
// capabilities.extendedAgentCard == true. Read-only; never creates tasks.
// Returns exposure signals to add (caller merges them).
func probeExtendedCard(ctx context.Context, client *http.Client, result *A2AProbeResult) []string {
	// Find the first JSON-RPC-capable interface
	var rpcURL string
	for _, iface := range result.Interfaces {
		if shouldProbeA2AJSONRPC(iface) {
			rpcURL = iface.URL
			break
		}
	}
	if rpcURL == "" {
		return nil
	}

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "GetExtendedAgentCard",
		"params":  map[string]interface{}{},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("A2A-Version", firstNonEmptyString(result.ProtocolVersion, "1.0"))
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.Header.Get("WWW-Authenticate") != "" {
		return []string{"extended_card_auth_required"}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(raw, &rpcResp); err != nil {
		return nil
	}
	// Method not found = extended card endpoint exists but doesn't expose extended data
	if errMap, ok := rpcResp["error"].(map[string]interface{}); ok {
		code := fmt.Sprint(errMap["code"])
		msg := strings.ToLower(fmt.Sprint(errMap["message"]))
		if code == "-32601" || strings.Contains(msg, "method not found") || strings.Contains(msg, "not supported") {
			return []string{"extended_card_not_found"}
		}
		return []string{"extended_card_auth_required"}
	}
	// Got a result without auth = exposed
	if rpcResp["result"] != nil {
		return []string{"extended_card_no_auth"}
	}
	return nil
}

func relevantA2AHeaders(headers http.Header) map[string]string {
	keys := []string{"Content-Type", "Server", "WWW-Authenticate", "A2A-Version", "A2A-Extensions", "Location"}
	out := make(map[string]string)
	for _, key := range keys {
		if value := headers.Get(key); value != "" {
			out[http.CanonicalHeaderKey(key)] = value
		}
	}
	return out
}

func stringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func mapField(m map[string]interface{}, key string) map[string]interface{} {
	v, _ := m[key].(map[string]interface{})
	return v
}

func stringSliceField(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func isPrivateA2AHost(host string) bool {
	host = strings.Trim(host, "[]")
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}

func looksA2AEndpointPath(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "/a2a") || strings.Contains(path, "/rpc") || strings.Contains(path, "/jsonrpc")
}

func mustURLPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

func boolLike(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

func hasSystemAdminSkill(skills []models.A2ASkill) bool {
	keywords := []string{"system", "admin", "command", "update", "backup", "shell", "terminal", "delete", "file", "root", "sudo"}
	for _, skill := range skills {
		text := strings.ToLower(skill.ID + " " + skill.Name + " " + skill.Description + " " + strings.Join(skill.Tags, " "))
		for _, keyword := range keywords {
			if strings.Contains(text, keyword) {
				return true
			}
		}
	}
	return false
}
