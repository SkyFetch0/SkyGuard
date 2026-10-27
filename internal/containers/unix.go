package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// unixClient speaks HTTP to a daemon over its unix socket.
type unixClient struct {
	http   *http.Client
	host   string // the Host header; the address is the socket
	socket string
}

func newUnixClient(socket, host string) *unixClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	// No client-wide timeout: stopping a container legitimately takes as long
	// as its stop timeout. Every call carries a context deadline instead.
	return &unixClient{http: &http.Client{Transport: tr}, host: host, socket: socket}
}

// response is a raw reply: the status, headers and (capped) body.
type response struct {
	status int
	header http.Header
	body   []byte
}

func (c *unixClient) do(ctx context.Context, method, path string, query url.Values, body any, header http.Header) (*response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := "http://" + c.host + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s %s: %w", method, path, err)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}
