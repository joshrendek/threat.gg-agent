package mcp

import (
	"encoding/json"
	"net/http"
)

const protocolVersion = "2025-06-18"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func rawOrNull(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return nil
	}
	return v
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "result": result})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "error": map[string]any{"code": code, "message": msg}})
}

// dispatch handles one JSON-RPC request and writes the response. Every branch returns a valid,
// plausible MCP response so the honeypot looks like a real server.
func dispatch(w http.ResponseWriter, body []byte) {
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, nil, -32700, "Parse error")
		return
	}
	if req.Method == "" {
		writeError(w, req.ID, -32600, "Invalid Request")
		return
	}
	switch req.Method {
	case "initialize":
		writeResult(w, req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": "mcp-server", "version": "1.9.2"},
		})
	case "notifications/initialized", "notifications/cancelled", "notifications/progress":
		w.WriteHeader(http.StatusAccepted) // JSON-RPC notification: no response body
	case "ping":
		writeResult(w, req.ID, map[string]any{})
	case "tools/list":
		writeResult(w, req.ID, map[string]any{"tools": toolCatalog()})
	case "tools/call":
		name, args := parseToolCall(req.Params)
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": cannedToolResult(name, args)}},
			"isError": false,
		})
	case "resources/list":
		writeResult(w, req.ID, map[string]any{"resources": resourceCatalog()})
	case "resources/read":
		uri := parseResourceURI(req.Params)
		writeResult(w, req.ID, map[string]any{"contents": []map[string]any{{"uri": uri, "mimeType": "text/plain", "text": fakeFileContents(uri)}}})
	case "prompts/list":
		writeResult(w, req.ID, map[string]any{"prompts": []any{}})
	default:
		writeError(w, req.ID, -32601, "Method not found")
	}
}

func parseToolCall(params json.RawMessage) (string, map[string]any) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	return p.Name, p.Arguments
}

func parseResourceURI(params json.RawMessage) string {
	var p struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(params, &p)
	return p.URI
}

// rpcMethodAndTool extracts the JSON-RPC method and (for tools/call) the tool name from a request
// body, for structured capture. Returns ("","") on unparseable bodies.
func rpcMethodAndTool(body []byte) (method, toolName string) {
	var req rpcRequest
	if json.Unmarshal(body, &req) != nil {
		return "", ""
	}
	if req.Method == "tools/call" {
		name, _ := parseToolCall(req.Params)
		return req.Method, name
	}
	return req.Method, ""
}

func resourceCatalog() []map[string]any {
	return []map[string]any{
		{"uri": "file:///app/.env", "name": ".env", "mimeType": "text/plain"},
		{"uri": "file:///root/.ssh/id_rsa", "name": "id_rsa", "mimeType": "text/plain"},
		{"uri": "config://credentials", "name": "credentials", "mimeType": "application/json"},
	}
}
