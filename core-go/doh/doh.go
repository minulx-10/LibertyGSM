// Package doh is a DNS-over-HTTPS resolver (RFC 8484, application/dns-message):
// the raw DNS query bytes ARE the POST body and the raw response bytes come
// back. It's the second piece of the portable core, shared by every platform
// engine.
//
// Unlike the Python port, no hand-built connection pool is needed: Go's
// net/http.Transport already pools keep-alive connections and negotiates HTTP/2
// automatically, so concurrent Resolve calls are multiplexed for free.
package doh

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const mimeDNS = "application/dns-message"

// DefaultEndpoints are DoH resolvers addressed by literal IP so resolving the
// resolver never needs DNS. 1.0.0.1 / 8.8.4.4 are secondary anycast IPs: many
// school/ISP networks block 1.1.1.1 specifically but not its sibling. The TLS
// certificates include IP SANs, so verification still succeeds.
var DefaultEndpoints = []string{
	"https://1.0.0.1/dns-query",
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://8.8.4.4/dns-query",
}

// Client resolves DNS queries over DoH, failing over across endpoints.
type Client struct {
	endpoints []string
	http      *http.Client

	mu     sync.Mutex
	active int
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying http.Client (used in tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// New builds a Client over the given endpoints (DefaultEndpoints if empty).
func New(endpoints []string, opts ...Option) *Client {
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	c := &Client{
		endpoints: append([]string(nil), endpoints...),
		http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Client) activeEndpoint() (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active, c.endpoints[c.active]
}

func (c *Client) rotate(failedIdx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == failedIdx { // only rotate if nobody else already did
		c.active = (c.active + 1) % len(c.endpoints)
	}
}

// Resolve POSTs a raw DNS query (wire format) over DoH and returns the raw
// response. It tries the active endpoint first, rotating to the next on failure.
func (c *Client) Resolve(query []byte) ([]byte, error) {
	var lastErr error
	for range c.endpoints {
		idx, url := c.activeEndpoint()
		resp, err := c.post(url, query)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		c.rotate(idx)
	}
	if lastErr == nil {
		lastErr = errors.New("doh: no endpoints configured")
	}
	return nil, lastErr
}

func (c *Client) post(url string, query []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mimeDNS)
	req.Header.Set("Accept", mimeDNS)
	req.Header.Set("User-Agent", "LibertyGSM")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("doh: HTTP " + resp.Status)
	}
	if len(body) == 0 {
		return nil, errors.New("doh: empty response")
	}
	return body, nil
}

// Probe checks the upstream is reachable by resolving example.com A.
func (c *Client) Probe() error {
	query := []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	_, err := c.Resolve(query)
	return err
}
