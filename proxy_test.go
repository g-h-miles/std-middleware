// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStdProxy(t *testing.T) {
	t1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "target 1")
	}))
	defer t1.Close()
	url1, _ := url.Parse(t1.URL)
	t2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "target 2")
	}))
	defer t2.Close()
	url2, _ := url.Parse(t2.URL)
	targets := []*StdProxyTarget{{Name: "target 1", URL: url1}, {Name: "target 2", URL: url2}}

	rb := NewStdRandomBalancer(nil)
	for _, tgt := range targets {
		if !rb.AddTarget(tgt) {
			t.Fatalf("expected target %s to be added", tgt.Name)
		}
	}
	for _, tgt := range targets {
		if rb.AddTarget(tgt) {
			t.Fatalf("expected duplicate target %s to be rejected", tgt.Name)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", ProxyStd(rb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	expected := map[string]bool{"target 1": true, "target 2": true}
	if !expected[body] {
		t.Fatalf("unexpected body %s", body)
	}

	for _, tgt := range targets {
		if !rb.RemoveTarget(tgt.Name) {
			t.Fatalf("expected target %s to be removed", tgt.Name)
		}
	}
	if rb.RemoveTarget("unknown") {
		t.Fatalf("expected remove unknown target to fail")
	}

	rrb := NewStdRoundRobinBalancer(targets)
	mux = http.NewServeMux()
	mux.Handle("/", ProxyStd(rrb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "target 1" {
		t.Fatalf("expected target 1 got %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "target 2" {
		t.Fatalf("expected target 2 got %s", rec.Body.String())
	}

	mux = http.NewServeMux()
	mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
		Balancer: rrb,
		ModifyResponse: func(res *http.Response) error {
			res.Body = io.NopCloser(bytes.NewBuffer([]byte("modified")))
			res.Header.Set("X-Modified", "1")
			return nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "modified" {
		t.Fatalf("expected body modified got %s", rec.Body.String())
	}
	if rec.Header().Get("X-Modified") != "1" {
		t.Fatalf("expected header X-Modified=1 got %s", rec.Header().Get("X-Modified"))
	}
}

type stdTestProvider struct {
	stdCommonBalancer
	target *StdProxyTarget
	err    error
}

func (p *stdTestProvider) Next(r *http.Request) *StdProxyTarget { return &StdProxyTarget{} }
func (p *stdTestProvider) NextTarget(r *http.Request) (*StdProxyTarget, error) {
	return p.target, p.err
}

func TestStdTargetProvider(t *testing.T) {
	t1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "target 1")
	}))
	defer t1.Close()
	url1, _ := url.Parse(t1.URL)

	tp := &stdTestProvider{target: &StdProxyTarget{Name: "target 1", URL: url1}}

	mux := http.NewServeMux()
	mux.Handle("/", ProxyStd(tp)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "target 1" {
		t.Fatalf("expected target 1 got %s", rec.Body.String())
	}
}

func TestStdFailNextTarget(t *testing.T) {
	url1, _ := url.Parse("http://dummy:8080")
	tp := &stdTestProvider{target: &StdProxyTarget{Name: "target 1", URL: url1}, err: errors.New("method could not select target")}

	mux := http.NewServeMux()
	mux.Handle("/", ProxyStd(tp)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected %d got %d", http.StatusBadGateway, rec.Code)
	}
}

func TestStdProxyRewrite(t *testing.T) {
	tests := []struct {
		whenPath     string
		expectURI    string
		expectStatus int
	}{
		{"/api/users", "/users", http.StatusOK},
		{"/js/main.js", "/public/javascripts/main.js", http.StatusOK},
		{"/old", "/new", http.StatusOK},
		{"/users/jack/orders/1", "/user/jack/order/1", http.StatusOK},
		{"/api/new users", "/new%20users", http.StatusOK},
		{"/api/users?limit=10", "/users?limit=10", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.whenPath, func(t *testing.T) {
			received := make(chan string, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.RequestURI
			}))
			defer upstream.Close()
			serverURL, _ := url.Parse(upstream.URL)
			rrb := NewStdRoundRobinBalancer([]*StdProxyTarget{{Name: "upstream", URL: serverURL}})

			mux := http.NewServeMux()
			mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
				Balancer: rrb,
				Rewrite: map[string]string{
					"/old":              "/new",
					"/api/*":            "/$1",
					"/js/*":             "/public/javascripts/$1",
					"/users/*/orders/*": "/user/$1/order/$2",
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

			targetURL, _ := serverURL.Parse(tc.whenPath)
			req := httptest.NewRequest(http.MethodGet, targetURL.String(), nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.expectStatus {
				t.Fatalf("expected %d got %d", tc.expectStatus, rec.Code)
			}
			actual := <-received
			if actual != tc.expectURI {
				t.Fatalf("expected %s got %s", tc.expectURI, actual)
			}
		})
	}
}

func TestStdProxyRewriteRegex(t *testing.T) {
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.RequestURI
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	rrb := NewStdRoundRobinBalancer([]*StdProxyTarget{{Name: "upstream", URL: u}})

	mux := http.NewServeMux()
	mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
		Balancer: rrb,
		Rewrite: map[string]string{
			"^/unmatched":     "/unmatched",
			"^/a/(.*)":        "/v1/$1",
			"^/b/(.*)/c/(.*)": "/v2/$2/$1",
			"^/c/.*":          "/v3/$1",
			"^/x/.*/(.*)":     "/v4/$1",
			"^/y/(.*)/(.*)":   "/v5/$2/$1",
		},
		RegexRewrite: map[*regexp.Regexp]string{
			regexp.MustCompile(`^/c/ignore(.*)`): "/v3$1",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	cases := []struct {
		path   string
		status int
		expect string
	}{
		{"/unmatched", http.StatusOK, "/unmatched"},
		{"/a/test", http.StatusOK, "/v1/test"},
		{"/b/foo/c/bar/baz", http.StatusOK, "/v2/bar/baz/foo"},
		{"/c/ignore/test", http.StatusOK, "/v3/test"},
		{"/c/ignore1/test/this", http.StatusOK, "/v31/test/this"},
		{"/x/ignore/test", http.StatusOK, "/v4/test"},
		{"/y/foo/bar", http.StatusOK, "/v5/bar/foo"},
		{"/y/foo/bar?q=1#frag", http.StatusOK, "/v5/bar?q=1"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			targetURL, _ := url.Parse(tc.path)
			req := httptest.NewRequest(http.MethodGet, targetURL.String(), nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			actual := <-received
			if actual != tc.expect {
				t.Fatalf("expected %s got %s", tc.expect, actual)
			}
			if rec.Code != tc.status {
				t.Fatalf("expected %d got %d", tc.status, rec.Code)
			}
		})
	}
}

func TestStdProxyError(t *testing.T) {
	url1, _ := url.Parse("http://127.0.0.1:27121")
	url2, _ := url.Parse("http://127.0.0.1:27122")
	targets := []*StdProxyTarget{{Name: "1", URL: url1}, {Name: "2", URL: url2}}
	rb := NewStdRandomBalancer(nil)
	for _, tgt := range targets {
		if !rb.AddTarget(tgt) {
			t.Fatalf("expected target %s to be added", tgt.Name)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/", ProxyStd(rb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected %d got %d", http.StatusBadGateway, rec.Code)
	}
}

func TestStdProxyRetries(t *testing.T) {
	newServer := func(res int) (*url.URL, *httptest.Server) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(res)
		}))
		targetURL, _ := url.Parse(server.URL)
		return targetURL, server
	}

	targetURL, server := newServer(http.StatusOK)
	defer server.Close()
	goodTarget := &StdProxyTarget{Name: "Good", URL: targetURL}

	targetURL, server = newServer(http.StatusBadRequest)
	defer server.Close()
	goodTarget40X := &StdProxyTarget{Name: "Bad", URL: targetURL}

	targetURL, _ = url.Parse("http://127.0.0.1:27121")
	badTarget := &StdProxyTarget{Name: "Bad", URL: targetURL}

	always := func(r *http.Request, e error) bool { return true }
	never := func(r *http.Request, e error) bool { return false }

	cases := []struct {
		name       string
		retryCount int
		filters    []func(*http.Request, error) bool
		targets    []*StdProxyTarget
		expected   int
	}{
		{"retry count 0 does not retry", 0, nil, []*StdProxyTarget{badTarget, goodTarget}, http.StatusBadGateway},
		{"retry count 1 retries", 1, []func(*http.Request, error) bool{always}, []*StdProxyTarget{badTarget, goodTarget}, http.StatusOK},
		{"multiple retries", 3, []func(*http.Request, error) bool{always, always, always}, []*StdProxyTarget{badTarget, badTarget, badTarget, goodTarget}, http.StatusOK},
		{"40x responses are not retried", 1, nil, []*StdProxyTarget{goodTarget40X, goodTarget}, http.StatusBadRequest},
		{"custom retry filter", 1, []func(*http.Request, error) bool{never}, []*StdProxyTarget{badTarget, goodTarget}, http.StatusBadGateway},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := 0
			rf := func(r *http.Request, e error) bool {
				if len(tc.filters) == 0 {
					t.Fatalf("unexpected call")
				}
				f := tc.filters[0]
				tc.filters = tc.filters[1:]
				call++
				return f(r, e)
			}
			bal := NewStdRoundRobinBalancer(tc.targets)
			mux := http.NewServeMux()
			mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
				Balancer:    bal,
				RetryCount:  tc.retryCount,
				RetryFilter: rf,
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.expected {
				t.Fatalf("expected %d got %d", tc.expected, rec.Code)
			}
			if len(tc.filters) > 0 {
				t.Fatalf("expected more retry filter calls")
			}
		})
	}
}

func TestStdProxyRetryWithBackendTimeout(t *testing.T) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 500 * time.Millisecond

	timeoutBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(404)
	}))
	defer timeoutBackend.Close()
	timeoutURL, _ := url.Parse(timeoutBackend.URL)

	goodBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer goodBackend.Close()
	goodURL, _ := url.Parse(goodBackend.URL)

	mux := http.NewServeMux()
	mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
		Transport:  transport,
		Balancer:   NewStdRoundRobinBalancer([]*StdProxyTarget{{Name: "Timeout", URL: timeoutURL}, {Name: "Good", URL: goodURL}}),
		RetryCount: 1,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	var wg sync.WaitGroup
	errCh := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 200 {
				errCh <- fmt.Errorf("expected 200 got %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestStdProxyErrorHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	goodURL, _ := url.Parse(server.URL)
	defer server.Close()
	goodTarget := &StdProxyTarget{Name: "Good", URL: goodURL}

	badURL, _ := url.Parse("http://127.0.0.1:27121")
	badTarget := &StdProxyTarget{Name: "Bad", URL: badURL}

	transformedErr := errors.New("a new error")

	cases := []struct {
		name         string
		target       *StdProxyTarget
		errorHandler func(http.ResponseWriter, *http.Request, error)
		expect       func(*testing.T, error)
	}{
		{
			name:   "Error handler not invoked when request success",
			target: goodTarget,
			errorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
				t.Fatal("error handler should not be invoked")
			},
		},
		{
			name:   "Error handler invoked when request fails",
			target: badTarget,
			errorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
				if !strings.Contains(e.Error(), "502") {
					t.Fatalf("expected error to contain 502")
				}
				http.Error(w, transformedErr.Error(), http.StatusBadGateway)
			},
			expect: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), transformedErr.Error()) {
					t.Fatalf("expected %s in %s", transformedErr.Error(), err.Error())
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
				Balancer:     NewStdRoundRobinBalancer([]*StdProxyTarget{tc.target}),
				ErrorHandler: tc.errorHandler,
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if tc.expect != nil {
				tc.expect(t, errors.New(rec.Body.String()))
			}
		})
	}
}

func TestStdClientCancelConnectionResultsHTTPCode499(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Wait()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()
	targetURL, _ := url.Parse(targetSrv.URL)

	rb := NewStdRandomBalancer([]*StdProxyTarget{{Name: "target", URL: targetURL}})
	mux := http.NewServeMux()
	mux.Handle("/", ProxyStd(rb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	mux.ServeHTTP(rec, req)
	wg.Done()
	if rec.Code != StatusCodeContextCanceled {
		t.Fatalf("expected %d got %d", StatusCodeContextCanceled, rec.Code)
	}
}

func TestStdProxyBalancerWithNoTargets(t *testing.T) {
	rb := NewStdRandomBalancer(nil)
	if rb.Next(nil) != nil {
		t.Fatalf("expected nil target")
	}
	rrb := NewStdRoundRobinBalancer([]*StdProxyTarget{})
	if rrb.Next(nil) != nil {
		t.Fatalf("expected nil target")
	}
}

type stdTestContextKey string

type stdCustomBalancer struct{ target *StdProxyTarget }

func (b *stdCustomBalancer) AddTarget(tgt *StdProxyTarget) bool { return false }
func (b *stdCustomBalancer) RemoveTarget(name string) bool      { return false }
func (b *stdCustomBalancer) Next(r *http.Request) *StdProxyTarget {
	ctx := context.WithValue(r.Context(), stdTestContextKey("FROM_BALANCER"), "CUSTOM_BALANCER")
	*r = *r.WithContext(ctx)
	return b.target
}

func TestStdModifyResponseUseContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()
	targetURL, _ := url.Parse(server.URL)
	mux := http.NewServeMux()
	mux.Handle("/", ProxyStdWithConfig(StdProxyConfig{
		Balancer:   &stdCustomBalancer{target: &StdProxyTarget{Name: "tst", URL: targetURL}},
		RetryCount: 1,
		ModifyResponse: func(res *http.Response) error {
			if val, ok := res.Request.Context().Value(stdTestContextKey("FROM_BALANCER")).(string); ok {
				res.Header.Set("FROM_BALANCER", val)
			}
			return nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rec.Code)
	}
	if rec.Body.String() != "OK" {
		t.Fatalf("expected body OK got %s", rec.Body.String())
	}
	if rec.Header().Get("FROM_BALANCER") != "CUSTOM_BALANCER" {
		t.Fatalf("expected FROM_BALANCER CUSTOM_BALANCER got %s", rec.Header().Get("FROM_BALANCER"))
	}
}
