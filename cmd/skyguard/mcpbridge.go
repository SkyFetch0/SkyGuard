package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// The stdio bridge lets an MCP client that only launches local commands
// (one JSON-RPC message per line on stdin and stdout) talk to SkyGuard's
// /mcp HTTP endpoint, for example over SSH:
//
//	ssh admin@server docker exec -i -e SKYGUARD_MCP_TOKEN=… skyguard skyguard -mcp-stdio
//
// stdout carries only protocol messages; anything for a human goes to stderr.

// mcpEndpoint picks the URL: SKYGUARD_MCP_URL, else the dashboard address
// from the config file, else the default.
func mcpEndpoint(configPath string) string {
	if u := os.Getenv("SKYGUARD_MCP_URL"); u != "" {
		return u
	}
	if cfg, err := config.LoadConfig(configPath); err == nil {
		if host, port, err := net.SplitHostPort(cfg.Dashboard.Listen); err == nil {
			if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
				host = "127.0.0.1"
			}
			return "http://" + net.JoinHostPort(host, port) + "/mcp"
		}
	}
	return "http://" + config.DefaultDashboardListen + "/mcp"
}

func mcpToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := os.Getenv("SKYGUARD_MCP_TOKEN"); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("no token: set SKYGUARD_MCP_TOKEN or pass -mcp-token-file (make one in SkyGuard's Settings → AI assistants)")
}

type mcpBridge struct {
	endpoint, token string
	client          *http.Client
	session         string // Mcp-Session-Id, if the server hands one out
	protocol        string // MCP-Protocol-Version, from the initialize reply
	out             io.Writer
	log             io.Writer
}

// run relays messages until stdin closes. Messages are handled in order.
func (b *mcpBridge) run(in io.Reader) error {
	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if msg := bytes.TrimSpace(line); len(msg) > 0 {
			b.relay(msg)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (b *mcpBridge) relay(msg []byte) {
	var head struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(msg, &head); err != nil {
		// JSON-RPC answers unparseable input with a null id.
		b.reply(json.RawMessage("null"), -32700, "parse error: "+err.Error())
		return
	}
	req, err := http.NewRequest("POST", b.endpoint, bytes.NewReader(msg))
	if err != nil {
		b.reply(head.ID, -32603, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+b.token)
	if b.session != "" {
		req.Header.Set("Mcp-Session-Id", b.session)
	}
	if b.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", b.protocol)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.reply(head.ID, -32000, "SkyGuard is not reachable at "+b.endpoint+": "+err.Error())
		return
	}
	defer resp.Body.Close()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		b.session = s
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return // a notification or a response from the client: nothing comes back
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		var e struct{ Error string }
		text := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			text = e.Error
		}
		b.reply(head.ID, -32000, fmt.Sprintf("SkyGuard answered %d: %s", resp.StatusCode, text))
		return
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		b.relayEvents(resp.Body, head.Method)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		b.reply(head.ID, -32000, "reading SkyGuard's reply: "+err.Error())
		return
	}
	b.emit(body, head.Method)
}

// relayEvents forwards each SSE event's data as one message.
func (b *mcpBridge) relayEvents(body io.Reader, method string) {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var data []string
	flush := func() {
		if len(data) > 0 {
			b.emit([]byte(strings.Join(data, "\n")), method)
			data = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
}

// emit writes one message on its own line, remembering the protocol version
// the server chose at initialize.
func (b *mcpBridge) emit(body []byte, method string) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, bytes.TrimSpace(body)); err != nil || compact.Len() == 0 {
		fmt.Fprintf(b.log, "skyguard mcp bridge: ignoring a reply that is not JSON (%d bytes)\n", len(body))
		return
	}
	if method == "initialize" {
		var init struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if json.Unmarshal(compact.Bytes(), &init) == nil && init.Result.ProtocolVersion != "" {
			b.protocol = init.Result.ProtocolVersion
		}
	}
	compact.WriteByte('\n')
	_, _ = b.out.Write(compact.Bytes())
}

// reply answers a request with a JSON-RPC error, so the client does not wait
// forever; a failed notification is only logged.
func (b *mcpBridge) reply(id json.RawMessage, code int, msg string) {
	fmt.Fprintln(b.log, "skyguard mcp bridge:", msg)
	if len(id) == 0 {
		return
	}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	_, _ = b.out.Write(append(out, '\n'))
}

func runMCPBridge(configPath, tokenFile string) int {
	token, err := mcpToken(tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skyguard mcp bridge:", err)
		return 1
	}
	b := &mcpBridge{endpoint: mcpEndpoint(configPath), token: token, client: &http.Client{Timeout: 5 * time.Minute}, out: os.Stdout, log: os.Stderr}
	fmt.Fprintln(os.Stderr, "skyguard mcp bridge: relaying stdio to", b.endpoint)
	if err := b.run(os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "skyguard mcp bridge:", err)
		return 1
	}
	return 0
}
