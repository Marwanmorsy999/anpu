package http

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	stdhttp "net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyPool implements RoundRobin proxy rotation with health checking.
// Each request picks the next healthy proxy; failed proxies are
// temporarily marked unhealthy and retried after a cooldown.
type ProxyPool struct {
	mu       sync.Mutex
	proxies  []*url.URL
	healthy  map[string]time.Time // proxy URL -> unhealthy until
	index    int
	cooldown time.Duration
}

// NewProxyPool parses proxy URLs (one per line, # comments ignored)
// from a file at path. Empty lines and comments are skipped.
// Supports http, https, socks5 schemes.
func NewProxyPool(path string) (*ProxyPool, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, fmt.Errorf("opening proxy pool %q: %w", path, err)
	}
	defer f.Close()
	var urls []*url.URL
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			continue
		}
		if u.Host == "" {
			continue
		}
		urls = append(urls, u)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("proxy pool %q contains no valid proxies", path)
	}
	return &ProxyPool{
		proxies:  urls,
		healthy:  make(map[string]time.Time),
		cooldown: 30 * time.Second,
	}, nil
}

// NewProxyPoolFromSlice builds a pool from an in-memory slice (for tests).
func NewProxyPoolFromSlice(raw []string) (*ProxyPool, error) {
	var urls []*url.URL
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid proxies")
	}
	return &ProxyPool{proxies: urls, healthy: make(map[string]time.Time), cooldown: 30 * time.Second}, nil
}

// Next returns the next healthy proxy URL in RoundRobin order.
// It skips proxies marked unhealthy until their cooldown expires.
func (p *ProxyPool) Next() *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proxies) == 0 {
		return nil
	}
	now := time.Now()
	for i := 0; i < len(p.proxies); i++ {
		idx := (p.index + i) % len(p.proxies)
		u := p.proxies[idx]
		if until, bad := p.healthy[u.String()]; bad && now.Before(until) {
			continue
		}
		p.index = (idx + 1) % len(p.proxies)
		return u
	}
	// All unhealthy — return next anyway (fail-open to first).
	u := p.proxies[p.index%len(p.proxies)]
	p.index = (p.index + 1) % len(p.proxies)
	return u
}

// MarkBad marks a proxy as unhealthy for the cooldown duration.
func (p *ProxyPool) MarkBad(u *url.URL) {
	if u == nil {
		return
	}
	p.mu.Lock()
	p.healthy[u.String()] = time.Now().Add(p.cooldown)
	p.mu.Unlock()
}

// MarkGood clears unhealthy status.
func (p *ProxyPool) MarkGood(u *url.URL) {
	if u == nil {
		return
	}
	p.mu.Lock()
	delete(p.healthy, u.String())
	p.mu.Unlock()
}

// Size returns number of proxies.
func (p *ProxyPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.proxies)
}

// PoolTransport is a RoundTripper that rotates proxies per request
// via the pool. It delegates to the underlying transport for non-proxy
// logic but swaps the Proxy func per request.
type PoolTransport struct {
	base *stdhttp.Transport
	pool *ProxyPool
}

// NewPoolTransport wraps a base transport with pool rotation.
func NewPoolTransport(base *stdhttp.Transport, pool *ProxyPool) *PoolTransport {
	if base == nil {
		base = &stdhttp.Transport{}
	}
	return &PoolTransport{base: base, pool: pool}
}

func (t *PoolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pu := t.pool.Next()
	if pu == nil {
		return t.base.RoundTrip(req)
	}
	// For SOCKS5, we need to use x/net/proxy dialer; for http/https use
	// standard ProxyURL behavior. Clone per-request so concurrent requests
	// don't race on Proxy func.
	clone := req.Clone(req.Context())
	_ = clone // keep for future per-request proxy injection if needed
	// Temporarily set pool's current choice as the transport proxy for
	// this request via context? Simpler: override transport.Proxy for this
	// call under lock — but that's racy. Instead, we dial via SOCKS if needed.
	if strings.EqualFold(pu.Scheme, "socks5") || strings.EqualFold(pu.Scheme, "socks5h") {
		dialer, err := proxy.FromURL(pu, proxy.Direct)
		if err == nil {
			// Use SOCKS dialer for this request. We can't easily swap
			// Transport.DialContext per-request without cloning the
			// transport, so we clone it.
			tcopy := t.base.Clone()
			tcopy.Proxy = nil // direct, we dial via SOCKS
			tcopy.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				// proxy.Dial is blocking, not context-aware; run with context.
				type result struct {
					conn net.Conn
					err  error
				}
				ch := make(chan result, 1)
				go func() {
					c, e := dialer.Dial(network, address)
					ch <- result{c, e}
				}()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case r := <-ch:
					return r.conn, r.err
				}
			}
			// Use a one-off client transport for this request
			resp, err := (&stdhttp.Transport{
				Proxy:                 tcopy.Proxy,
				DialContext:           tcopy.DialContext,
				TLSClientConfig:       tcopy.TLSClientConfig,
				MaxIdleConnsPerHost:   tcopy.MaxIdleConnsPerHost,
				ResponseHeaderTimeout: tcopy.ResponseHeaderTimeout,
				ForceAttemptHTTP2:     tcopy.ForceAttemptHTTP2,
			}).RoundTrip(req)
			if err != nil {
				t.pool.MarkBad(pu)
			} else {
				t.pool.MarkGood(pu)
			}
			return resp, err
		}
	}
	// http/https proxy: clone transport with ProxyURL set to pu
	tcopy := t.base.Clone()
	tcopy.Proxy = stdhttp.ProxyURL(pu)
	resp, err := tcopy.RoundTrip(req)
	if err != nil {
		t.pool.MarkBad(pu)
	} else {
		t.pool.MarkGood(pu)
	}
	return resp, err
}

// WithProxyPool returns a copy of c that rotates through proxies
// listed in poolPath (one per line). Each request picks the next
// healthy proxy. Combines with GhostEnabled for header/JA3 rotation.
func (c *Client) WithProxyPool(poolPath string) (*Client, error) {
	poolPath = strings.TrimSpace(poolPath)
	if poolPath == "" {
		return c, nil
	}
	pool, err := NewProxyPool(poolPath)
	if err != nil {
		return nil, err
	}
	clone := *c
	clone.viaProxy = true
	GhostProxyPoolPath = poolPath
	if tr, ok := c.http.Transport.(*stdhttp.Transport); ok {
		tcopy := tr.Clone()
		poolRT := NewPoolTransport(tcopy, pool)
		// Need to expose poolRT as http.RoundTripper; wrap so safeDialContext still honors viaProxy
		tcopy.DialContext = clone.safeDialContext
		clone.http = &stdhttp.Client{
			Transport:     poolRT,
			Timeout:       c.http.Timeout,
			CheckRedirect: c.http.CheckRedirect,
		}
	} else if at, ok := c.http.Transport.(*authTransport); ok {
		if inner, ok := at.base.(*stdhttp.Transport); ok {
			tcopy := inner.Clone()
			poolRT := NewPoolTransport(tcopy, pool)
			clone.http = &stdhttp.Client{
				Transport: &authTransport{
					base:    poolRT,
					headers: at.headers,
				},
				Timeout:       c.http.Timeout,
				CheckRedirect: c.http.CheckRedirect,
			}
		} else if ghost, ok := at.base.(*GhostTransport); ok {
			if inner2, ok := ghost.base.(*stdhttp.Transport); ok {
				tcopy := inner2.Clone()
				poolRT := NewPoolTransport(tcopy, pool)
				ghost2 := &GhostTransport{base: poolRT, headerOrder: ghost.headerOrder, spec: ghost.spec}
				clone.http = &stdhttp.Client{
					Transport: &authTransport{
						base:    ghost2,
						headers: at.headers,
					},
					Timeout:       c.http.Timeout,
					CheckRedirect: c.http.CheckRedirect,
				}
			}
		}
	} else if ghost, ok := c.http.Transport.(*GhostTransport); ok {
		if inner, ok := ghost.base.(*stdhttp.Transport); ok {
			tcopy := inner.Clone()
			poolRT := NewPoolTransport(tcopy, pool)
			clone.http = &stdhttp.Client{
				Transport: &GhostTransport{
					base:        poolRT,
					headerOrder: ghost.headerOrder,
					spec:        ghost.spec,
				},
				Timeout:       c.http.Timeout,
				CheckRedirect: c.http.CheckRedirect,
			}
		}
	}
	return &clone, nil
}
