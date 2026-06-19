package llmtpl

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// jsonGet resolves a simplified dot-path against a parsed JSON value.
//
// Supported grammar:
//
//	path     = segment ("." segment)*
//	segment  = key | key "[" index "]"
//	key      = alphanumeric + underscore
//	index    = number | "*"
//
// Examples:
//   - "version"           → data["version"]
//   - "data[0].id"        → data["data"][0]["id"]
//   - "models[*].name"    → all elements' "name" field, returned as []string
//   - "data[0].owned_by"  → data["data"][0]["owned_by"]
//
// Returns the value as interface{} and true if the path resolves.
// For wildcard [*], returns []interface{} of all matching values.
func jsonGet(data interface{}, path string) (interface{}, bool) {
	segments := parsePath(path)
	if len(segments) == 0 {
		return nil, false
	}
	return resolve(data, segments)
}

// jsonGetString resolves a path and returns it as a string.
// For arrays, elements are joined with commas.
func jsonGetString(data interface{}, path string) (string, bool) {
	val, ok := jsonGet(data, path)
	if !ok {
		return "", false
	}
	return valueToString(val), true
}

// jsonGetStringSlice resolves a path and returns it as a string slice.
// This is primarily for wildcard paths like "data[*].id".
func jsonGetStringSlice(data interface{}, path string) ([]string, bool) {
	val, ok := jsonGet(data, path)
	if !ok {
		return nil, false
	}
	switch v := val.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			result = append(result, valueToString(item))
		}
		return result, true
	default:
		s := valueToString(val)
		if s == "" {
			return nil, false
		}
		return []string{s}, true
	}
}

// ParseJSON parses a JSON byte slice into an interface{} suitable for jsonGet.
func ParseJSON(data []byte) (interface{}, error) {
	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ─── Internal ───────────────────────────────────────────────────────────────

type pathSegment struct {
	key      string
	hasIndex bool
	index    int  // -1 means wildcard [*]
}

func parsePath(path string) []pathSegment {
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil
	}

	var segments []pathSegment
	parts := splitPath(path)

	for _, part := range parts {
		seg := parseSegment(part)
		segments = append(segments, seg)
	}

	return segments
}

// splitPath splits on "." but respects brackets.
func splitPath(path string) []string {
	var parts []string
	var current strings.Builder
	inBracket := false

	for i := 0; i < len(path); i++ {
		ch := path[i]
		if ch == '[' {
			inBracket = true
			current.WriteByte(ch)
		} else if ch == ']' {
			inBracket = false
			current.WriteByte(ch)
		} else if ch == '.' && !inBracket {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

func parseSegment(s string) pathSegment {
	bracketStart := strings.IndexByte(s, '[')
	if bracketStart < 0 {
		return pathSegment{key: s}
	}

	key := s[:bracketStart]
	bracketEnd := strings.IndexByte(s[bracketStart:], ']')
	if bracketEnd < 0 {
		return pathSegment{key: s}
	}

	indexStr := s[bracketStart+1 : bracketStart+bracketEnd]
	if indexStr == "*" {
		return pathSegment{key: key, hasIndex: true, index: -1}
	}

	idx, err := strconv.Atoi(indexStr)
	if err != nil {
		return pathSegment{key: s}
	}
	return pathSegment{key: key, hasIndex: true, index: idx}
}

func resolve(data interface{}, segments []pathSegment) (interface{}, bool) {
	current := data

	for i, seg := range segments {
		if seg.key != "" {
			obj, ok := current.(map[string]interface{})
			if !ok {
				return nil, false
			}
			val, exists := obj[seg.key]
			if !exists {
				return nil, false
			}
			current = val
		}

		if seg.hasIndex {
			arr, ok := current.([]interface{})
			if !ok {
				return nil, false
			}

			if seg.index == -1 {
				// Wildcard: apply remaining path to all elements
				remaining := segments[i+1:]
				if len(remaining) == 0 {
					return arr, true
				}
				var results []interface{}
				for _, elem := range arr {
					val, ok := resolve(elem, remaining)
					if ok {
						results = append(results, val)
					}
				}
				if len(results) == 0 {
					return nil, false
				}
				return results, true
			}

			// Specific index
			if seg.index < 0 || seg.index >= len(arr) {
				return nil, false
			}
			current = arr[seg.index]
		}
	}

	return current, true
}

func valueToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return ""
	case []interface{}:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, valueToString(item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", val)
	}
}

// isDigit checks if all chars in s are digits.
func isDigit(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}
