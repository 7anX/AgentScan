package llmtpl

import (
	"regexp"
	"strconv"
	"strings"
)

// ResponseKey builds the map key for a response lookup: "METHOD PATH".
func ResponseKey(method, path string) string {
	if method == "" {
		method = "GET"
	}
	return method + " " + path
}

// ExtractVersion extracts a version string from raw response body/header
// using the version rules defined in a template.
func ExtractVersion(rules []VersionRule, responses map[string]*ProbeResponse) string {
	for _, rule := range rules {
		key := ResponseKey(rule.Method, rule.Path)
		resp, ok := responses[key]
		if !ok || resp == nil {
			continue
		}

		// Check matchers if any (precondition)
		if len(rule.Matchers) > 0 {
			cfg := responseToMatchConfig(resp)
			matched := false
			for _, m := range rule.Matchers {
				compiled, err := CompileRule(m)
				if err != nil {
					continue
				}
				if compiled.Eval(cfg) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Apply extractor
		version := applyExtractor(rule.Extractor, resp)
		if version != "" {
			return version
		}
	}
	return ""
}

// ExtractModels extracts model IDs from raw response body
// using the model rules defined in a template.
func ExtractModels(rules []ModelRule, responses map[string]*ProbeResponse) []string {
	for _, rule := range rules {
		key := ResponseKey(rule.Method, rule.Path)
		resp, ok := responses[key]
		if !ok || resp == nil {
			continue
		}

		// Check matchers if any
		if len(rule.Matchers) > 0 {
			cfg := responseToMatchConfig(resp)
			matched := false
			for _, m := range rule.Matchers {
				compiled, err := CompileRule(m)
				if err != nil {
					continue
				}
				if compiled.Eval(cfg) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Apply model extractor
		models := applyModelExtractor(rule.Extractor, resp)
		if len(models) > 0 {
			return models
		}
	}
	return nil
}

// applyExtractor applies a regex extractor to a response.
func applyExtractor(ext Extractor, resp *ProbeResponse) string {
	if ext.Regex == "" {
		return ""
	}

	var target string
	switch ext.Part {
	case "header":
		target = resp.HeaderRaw
	default: // "body" or empty
		target = resp.BodyStr
	}

	re, err := regexp.Compile(ext.Regex)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(target)
	group := ext.Group
	if group <= 0 {
		group = 1
	}
	if len(matches) > group {
		return matches[group]
	}
	return ""
}

// applyModelExtractor extracts a list of model IDs.
func applyModelExtractor(ext ModelExtractor, resp *ProbeResponse) []string {
	body := resp.Body

	switch ext.Type {
	case "json_array":
		return extractModelsJSON(body, ext.JSONPath)
	case "regex":
		return extractModelsRegex(string(body), ext.Regex, ext.Group)
	default:
		// Try json_array if json_path is set, else try regex
		if ext.JSONPath != "" {
			return extractModelsJSON(body, ext.JSONPath)
		}
		if ext.Regex != "" {
			return extractModelsRegex(string(body), ext.Regex, ext.Group)
		}
		return nil
	}
}

func extractModelsJSON(body []byte, jsonPath string) []string {
	parsed, err := ParseJSON(body)
	if err != nil {
		return nil
	}

	models, ok := jsonGetStringSlice(parsed, jsonPath)
	if !ok || len(models) == 0 {
		return nil
	}

	// Filter empty strings
	var result []string
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m != "" {
			result = append(result, m)
		}
	}
	return result
}

func extractModelsRegex(body, pattern string, group int) []string {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	if group <= 0 {
		group = 1
	}

	matches := re.FindAllStringSubmatch(body, -1)
	var result []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > group {
			val := strings.TrimSpace(m[group])
			if val != "" && !seen[val] {
				seen[val] = true
				result = append(result, val)
			}
		}
	}
	return result
}

// responseToMatchConfig converts a ProbeResponse to a MatchConfig for DSL evaluation.
func responseToMatchConfig(resp *ProbeResponse) *MatchConfig {
	return &MatchConfig{
		Body:       resp.BodyStr,
		Header:     resp.HeaderRaw,
		StatusCode: strconv.Itoa(resp.StatusCode),
	}
}

// ProbeResponse holds the raw HTTP response data.
type ProbeResponse struct {
	StatusCode int
	HeaderRaw  string // raw headers as string
	Body       []byte
	BodyStr    string // cached string(Body) — avoids repeated allocation
	ElapsedMs  float64
}

// NewProbeResponse creates a ProbeResponse with BodyStr auto-populated.
func NewProbeResponse(statusCode int, headerRaw string, body []byte, elapsedMs float64) *ProbeResponse {
	return &ProbeResponse{
		StatusCode: statusCode,
		HeaderRaw:  headerRaw,
		Body:       body,
		BodyStr:    string(body),
		ElapsedMs:  elapsedMs,
	}
}
