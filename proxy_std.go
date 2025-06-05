// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package middleware

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// StdProxyConfig defines configuration for the standard HTTP Proxy middleware.
type StdProxyConfig struct {
	Skipper        func(r *http.Request) bool
	Balancer       StdProxyBalancer
	RetryCount     int
	RetryFilter    func(r *http.Request, err error) bool
	ErrorHandler   func(http.ResponseWriter, *http.Request, error)
	Rewrite        map[string]string
	RegexRewrite   map[*regexp.Regexp]string
	ContextKey     string
	Transport      http.RoundTripper
	ModifyResponse func(*http.Response) error
}

type StdProxyTarget struct {
	Name string
	URL  *url.URL
	Meta map[string]interface{}
}

type StdProxyBalancer interface {
	AddTarget(*StdProxyTarget) bool
	RemoveTarget(string) bool
	Next(*http.Request) *StdProxyTarget
}

type StdTargetProvider interface {
	NextTarget(*http.Request) (*StdProxyTarget, error)
}

type stdCommonBalancer struct {
	targets []*StdProxyTarget
	mutex   sync.Mutex
}

type stdRandomBalancer struct {
	stdCommonBalancer
	random *rand.Rand
}

type stdRoundRobinBalancer struct {
	stdCommonBalancer
	i int
}

var DefaultStdProxyConfig = StdProxyConfig{
	Skipper:    func(*http.Request) bool { return false },
	ContextKey: "target",
}

func stdProxyRaw(t *StdProxyTarget, w http.ResponseWriter, r *http.Request, config StdProxyConfig) error {
	var dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	if transport, ok := config.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil {
			d := tls.Dialer{Config: transport.TLSClientConfig}
			dialFunc = d.DialContext
		}
	}
	if dialFunc == nil {
		var d net.Dialer
		dialFunc = d.DialContext
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("response does not support hijacking")
	}

	in, _, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("proxy raw, hijack error=%w, url=%s", err, t.URL)
	}
	defer in.Close()
	out, err := dialFunc(r.Context(), "tcp", t.URL.Host)
	if err != nil {
		return fmt.Errorf("proxy raw, dial error=%v, url=%s", err, t.URL)
	}
	defer out.Close()

	err = r.Write(out)
	if err != nil {
		return fmt.Errorf("proxy raw, request header copy error=%v, url=%s", err, t.URL)
	}

	errCh := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errCh <- err
	}

	go cp(out, in)
	go cp(in, out)
	err = <-errCh
	if err != nil && err != io.EOF {
		return fmt.Errorf("proxy raw, copy body error=%w, url=%s", err, t.URL)
	}
	return nil
}

func NewStdRandomBalancer(targets []*StdProxyTarget) StdProxyBalancer {
	b := stdRandomBalancer{}
	b.targets = targets
	b.random = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	return &b
}

func NewStdRoundRobinBalancer(targets []*StdProxyTarget) StdProxyBalancer {
	b := stdRoundRobinBalancer{}
	b.targets = targets
	return &b
}

func (b *stdCommonBalancer) AddTarget(target *StdProxyTarget) bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for _, t := range b.targets {
		if t.Name == target.Name {
			return false
		}
	}
	b.targets = append(b.targets, target)
	return true
}

func (b *stdCommonBalancer) RemoveTarget(name string) bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for i, t := range b.targets {
		if t.Name == name {
			b.targets = append(b.targets[:i], b.targets[i+1:]...)
			return true
		}
	}
	return false
}

func (b *stdRandomBalancer) Next(r *http.Request) *StdProxyTarget {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(b.targets) == 0 {
		return nil
	} else if len(b.targets) == 1 {
		return b.targets[0]
	}
	return b.targets[b.random.Intn(len(b.targets))]
}

func (b *stdRoundRobinBalancer) Next(r *http.Request) *StdProxyTarget {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(b.targets) == 0 {
		return nil
	} else if len(b.targets) == 1 {
		return b.targets[0]
	}

	var i int
	if val := r.Context().Value("_round_robin_last_index"); val != nil {
		i = val.(int)
		i++
		if i >= len(b.targets) {
			i = 0
		}
	} else {
		if b.i >= len(b.targets) {
			b.i = 0
		}
		i = b.i
		b.i++
	}

	*r = *r.WithContext(context.WithValue(r.Context(), "_round_robin_last_index", i))
	return b.targets[i]
}

const StatusCodeContextCanceled = 499

func stdProxyHTTP(tgt *StdProxyTarget, w http.ResponseWriter, r *http.Request, config StdProxyConfig) error {
	proxy := httputil.NewSingleHostReverseProxy(tgt.URL)
	var proxyErr error
	proxy.ErrorHandler = func(resp http.ResponseWriter, req *http.Request, err error) {
		desc := tgt.URL.String()
		if tgt.Name != "" {
			desc = fmt.Sprintf("%s(%s)", tgt.Name, tgt.URL.String())
		}
		if err == context.Canceled || strings.Contains(err.Error(), "operation was canceled") {
			proxyErr = fmt.Errorf("%d client closed connection: %v", StatusCodeContextCanceled, err)
		} else {
			proxyErr = fmt.Errorf("%d remote %s unreachable, could not forward: %v", http.StatusBadGateway, desc, err)
		}
	}
	proxy.Transport = config.Transport
	proxy.ModifyResponse = config.ModifyResponse
	proxy.ServeHTTP(w, r)
	return proxyErr
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func ProxyStd(balancer StdProxyBalancer) func(http.Handler) http.Handler {
	c := DefaultStdProxyConfig
	c.Balancer = balancer
	return ProxyStdWithConfig(c)
}

func ProxyStdWithConfig(config StdProxyConfig) func(http.Handler) http.Handler {
	if config.Balancer == nil {
		panic("proxy middleware requires balancer")
	}
	if config.Skipper == nil {
		config.Skipper = DefaultStdProxyConfig.Skipper
	}
	if config.RetryFilter == nil {
		config.RetryFilter = func(r *http.Request, e error) bool {
			return strings.HasPrefix(e.Error(), fmt.Sprintf("%d", http.StatusBadGateway))
		}
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			var code int
			fmt.Sscanf(err.Error(), "%d", &code)
			if code == 0 {
				code = http.StatusBadGateway
			}
			http.Error(w, http.StatusText(code), code)
		}
	}
	if config.Rewrite != nil {
		if config.RegexRewrite == nil {
			config.RegexRewrite = make(map[*regexp.Regexp]string)
		}
		for k, v := range rewriteRulesRegex(config.Rewrite) {
			config.RegexRewrite[k] = v
		}
	}

	provider, isTargetProvider := config.Balancer.(StdTargetProvider)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.Skipper(r) {
				next.ServeHTTP(w, r)
				return
			}

			if err := rewriteURL(config.RegexRewrite, r); err != nil {
				config.ErrorHandler(w, r, err)
				return
			}

			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if r.Header.Get("X-Real-Ip") == "" {
				r.Header.Set("X-Real-Ip", host)
			}
			if r.Header.Get("X-Forwarded-Proto") == "" {
				if r.TLS != nil {
					r.Header.Set("X-Forwarded-Proto", "https")
				} else {
					r.Header.Set("X-Forwarded-Proto", "http")
				}
			}
			if isWebSocketRequest(r) && r.Header.Get("X-Forwarded-For") == "" {
				r.Header.Set("X-Forwarded-For", host)
			}

			retries := config.RetryCount
			for {
				var tgt *StdProxyTarget
				var err error
				if isTargetProvider {
					tgt, err = provider.NextTarget(r)
					if err != nil {
						config.ErrorHandler(w, r, err)
						return
					}
				} else {
					tgt = config.Balancer.Next(r)
				}

				ctx := context.WithValue(r.Context(), config.ContextKey, tgt)
				r = r.WithContext(ctx)

				var proxyErr error
				if isWebSocketRequest(r) {
					proxyErr = stdProxyRaw(tgt, w, r, config)
				} else {
					proxyErr = stdProxyHTTP(tgt, w, r, config)
				}

				if proxyErr == nil {
					return
				}

				retry := retries > 0 && config.RetryFilter(r, proxyErr)
				if !retry {
					config.ErrorHandler(w, r, proxyErr)
					return
				}
				retries--
			}
		})
	}
}
