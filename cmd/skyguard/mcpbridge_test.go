package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoIn struct {
	Text string `json:"text"`
}

// mcpServer is a small MCP server behind a bearer check, answering in JSON
// or, with sse set, as an event stream.
func mcpServer(t *testing.T, sse bool) *httptest.Server {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"said": in.Text}, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: !sse})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"missing or wrong token"}`)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runBridge(t *testing.T, url, token string, lines ...string) []map[string]any {
	t.Helper()
	var out, logs bytes.Buffer
	b := &mcpBridge{endpoint: url, token: token, client: &http.Client{Timeout: 10 * time.Second}, out: &out, log: &logs}
	if err := b.run(strings.NewReader(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	var msgs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout carried something that is not one JSON message per line: %q", l)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

const (
	initMsg   = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	readyMsg  = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	listMsg   = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	callMsg   = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	brokenMsg = `{"jsonrpc":`
)

func TestMCPBridge(t *testing.T) {
	for _, sse := range []bool{false, true} {
		srv := mcpServer(t, sse)
		msgs := runBridge(t, srv.URL, "good", initMsg, readyMsg, listMsg, callMsg)
		if len(msgs) != 3 {
			t.Fatalf("sse=%v: want replies to initialize, tools/list and tools/call (the notification has none), got %v", sse, msgs)
		}
		if msgs[0]["result"].(map[string]any)["protocolVersion"] == nil {
			t.Errorf("initialize: %v", msgs[0])
		}
		tools := msgs[1]["result"].(map[string]any)["tools"].([]any)
		if len(tools) != 1 {
			t.Errorf("tools: %v", tools)
		}
		if sc := msgs[2]["result"].(map[string]any)["structuredContent"].(map[string]any); sc["said"] != "hi" {
			t.Errorf("call: %v", msgs[2])
		}
	}
}

func TestMCPBridgeErrorsReachTheClient(t *testing.T) {
	srv := mcpServer(t, false)
	msgs := runBridge(t, srv.URL, "bad", initMsg, brokenMsg)
	if len(msgs) != 2 {
		t.Fatalf("replies %v", msgs)
	}
	e := msgs[0]["error"].(map[string]any)
	if msgs[0]["id"].(float64) != 1 || !strings.Contains(e["message"].(string), "401") || !strings.Contains(e["message"].(string), "wrong token") {
		t.Errorf("a refused request must come back as a JSON-RPC error with its id: %v", msgs[0])
	}
	if msgs[1]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Errorf("malformed input: %v", msgs[1])
	}
	// SkyGuard down: the request is answered, not left hanging.
	down := runBridge(t, "http://127.0.0.1:1/mcp", "good", listMsg)
	if len(down) != 1 || !strings.Contains(down[0]["error"].(map[string]any)["message"].(string), "not reachable") {
		t.Errorf("unreachable: %v", down)
	}
}
