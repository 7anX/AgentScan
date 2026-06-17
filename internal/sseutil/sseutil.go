// Package sseutil provides shared SSE (Server-Sent Events) parsing utilities.
package sseutil

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// ParseFirstMessage reads an SSE stream and returns the JSON data of the first
// "message" event (or any unnamed event). Returns nil if no valid JSON event
// is found before EOF or read error.
func ParseFirstMessage(r io.Reader) map[string]interface{} {
	scanner := bufio.NewScanner(r)
	var eventType, dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "" && dataLine != "":
			// blank line = end of event
			if eventType == "" || eventType == "message" {
				var d map[string]interface{}
				if json.Unmarshal([]byte(dataLine), &d) == nil {
					return d
				}
			}
			eventType, dataLine = "", ""
		}
	}
	return nil
}

// ParseEndpointEvent reads a legacy HTTP+SSE stream and returns the data value
// of the first "endpoint" event (the POST URL path used by 2024-11-05 transport).
// Handles both well-formed SSE (blank-line terminated) and truncated responses
// where the server closes the connection without a trailing blank line.
func ParseEndpointEvent(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	var eventType, dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			if eventType == "endpoint" && dataLine != "" {
				return dataLine
			}
			eventType, dataLine = "", ""
		}
	}
	// EOF without trailing blank line: return whatever we have if it looks valid
	if eventType == "endpoint" && dataLine != "" {
		return dataLine
	}
	return ""
}
