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
//
// Handles:
//   - Large payloads: scanner buffer expanded to 512KB (same as ParseEndpointAndListen)
//   - Multi-line data: consecutive "data:" lines are concatenated per SSE spec
func ParseFirstMessage(r io.Reader) map[string]interface{} {
	scanner := bufio.NewScanner(r)
	// Expand buffer to 512KB to match ParseEndpointAndListen; prevents token too long
	// errors on servers that send large tool schemas in a single SSE event.
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	var eventType string
	var dataLines []string // accumulate multi-line data: fields

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			// SSE spec: multiple data: lines are joined with "\n"
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		case line == "":
			// blank line = dispatch event
			if len(dataLines) > 0 && (eventType == "" || eventType == "message") {
				payload := strings.Join(dataLines, "\n")
				var d map[string]interface{}
				if json.Unmarshal([]byte(payload), &d) == nil {
					return d
				}
			}
			eventType = ""
			dataLines = dataLines[:0]
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

// ParseEndpointAndListen reads a legacy HTTP+SSE stream, extracts the endpoint
// event path, then continuously reads message events and sends decoded JSON-RPC
// responses to msgCh. Blocks until the reader returns EOF or an error.
// Caller should close done channel to stop early; reader.Close() is preferred.
func ParseEndpointAndListen(r io.Reader, postPathCh chan<- string, msgCh chan<- map[string]interface{}) {
	scanner := bufio.NewScanner(r)
	// bufio.Scanner default buffer is 64KB; expand for large tool schemas
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	var eventType string
	var dataLines []string // multi-line data: accumulator
	endpointSent := false

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		case line == "":
			if len(dataLines) == 0 {
				eventType = ""
				continue
			}
			payload := strings.Join(dataLines, "\n")
			switch eventType {
			case "endpoint":
				if !endpointSent && payload != "" {
					select {
					case postPathCh <- payload:
						endpointSent = true
					default:
					}
				}
			case "message", "":
				var d map[string]interface{}
				if json.Unmarshal([]byte(payload), &d) == nil {
					select {
					case msgCh <- d:
					default:
					}
				}
			}
			eventType = ""
			dataLines = dataLines[:0]
		}
	}

	// EOF without trailing blank line
	if !endpointSent && eventType == "endpoint" && len(dataLines) > 0 {
		select {
		case postPathCh <- strings.Join(dataLines, "\n"):
		default:
		}
	}
}
