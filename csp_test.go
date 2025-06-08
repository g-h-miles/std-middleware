package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultCSPConfig(t *testing.T) {
	config := DefaultCSPConfig()

	if config == nil {
		t.Fatal("DefaultCSPConfig should not return nil")
	}

	// Test required security defaults
	if !contains(config.DefaultSrc, "'self'") {
		t.Error("Default config should include 'self' in default-src")
	}

	if !contains(config.ObjectSrc, "'none'") {
		t.Error("Default config should block objects")
	}

	if !contains(config.FrameAncestors, "'none'") {
		t.Error("Default config should prevent clickjacking")
	}

	if !config.UpgradeInsecureRequests {
		t.Error("Default config should upgrade insecure requests")
	}

	if !config.BlockAllMixedContent {
		t.Error("Default config should block mixed content")
	}

	// Test that img-src allows data URIs by default
	if !contains(config.ImgSrc, "data:") {
		t.Error("Default config should allow data URIs for images")
	}

	// Test that style-src allows unsafe-inline by default (practical default)
	if !contains(config.StyleSrc, "'unsafe-inline'") {
		t.Error("Default config should allow unsafe-inline styles for practicality")
	}
}

func TestStrictCSPConfig(t *testing.T) {
	config := StrictCSPConfig()

	if config == nil {
		t.Fatal("StrictCSPConfig should not return nil")
	}

	// Test strict defaults
	if !contains(config.DefaultSrc, "'none'") {
		t.Error("Strict config should have 'none' as default-src")
	}

	if !contains(config.ScriptSrc, "'strict-dynamic'") {
		t.Error("Strict config should use strict-dynamic for scripts")
	}

	if contains(config.StyleSrc, "'unsafe-inline'") {
		t.Error("Strict config should not allow unsafe-inline styles")
	}

	if !contains(config.RequireSriFor, "script") || !contains(config.RequireSriFor, "style") {
		t.Error("Strict config should require SRI for scripts and styles")
	}

	if !contains(config.FrameSrc, "'none'") {
		t.Error("Strict config should block frames by default")
	}
}

func TestConfigModification(t *testing.T) {
	// Test the main usage pattern - users modify config directly
	config := DefaultCSPConfig()

	// Add script sources
	config.ScriptSrc = append(config.ScriptSrc,
		"https://cdnjs.cloudflare.com",
		"https://unpkg.com",
		"'nonce-test123'",
	)

	// Add style sources
	config.StyleSrc = append(config.StyleSrc,
		"https://fonts.googleapis.com",
		"https://cdn.tailwindcss.com",
	)

	// Add image sources
	config.ImgSrc = append(config.ImgSrc,
		"https:",
		"blob:",
	)

	// Add connect sources
	config.ConnectSrc = append(config.ConnectSrc,
		"https://api.example.com",
		"wss://socket.example.com",
	)

	// Add reporting
	config.ReportURI = []string{"https://example.com/csp-report"}
	config.ReportTo = "csp-endpoint"

	// Test buildCSPString function
	cspString := buildCSPString(config, "")

	expectedParts := []string{
		"script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'nonce-test123'",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com",
		"img-src 'self' data: https: blob:",
		"connect-src 'self' https://api.example.com wss://socket.example.com",
		"report-uri https://example.com/csp-report",
		"report-to csp-endpoint",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspString, part) {
			t.Errorf("Expected CSP string to contain '%s', got: %s", part, cspString)
		}
	}
}

func TestDefaultCSPMiddleware(t *testing.T) {
	middleware := DefaultCSP()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	cspHeader := rr.Header().Get("Content-Security-Policy")

	if cspHeader == "" {
		t.Fatal("CSP header should be set")
	}

	// Should match the pre-computed default string
	if cspHeader != defaultCSPString {
		t.Errorf("Expected default CSP string, got: %s", cspHeader)
	}

	expectedParts := []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"upgrade-insecure-requests",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspHeader, part) {
			t.Errorf("Expected CSP header to contain '%s', got: %s", part, cspHeader)
		}
	}
}

func TestStrictCSPMiddleware(t *testing.T) {
	middleware := StrictCSP()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	cspHeader := rr.Header().Get("Content-Security-Policy")

	if cspHeader == "" {
		t.Fatal("CSP header should be set")
	}

	// Should match the pre-computed strict string
	if cspHeader != strictCSPString {
		t.Errorf("Expected strict CSP string, got: %s", cspHeader)
	}

	expectedParts := []string{
		"default-src 'none'",
		"script-src 'self' 'strict-dynamic'",
		"frame-src 'none'",
		"require-sri-for script style",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspHeader, part) {
			t.Errorf("Expected CSP header to contain '%s', got: %s", part, cspHeader)
		}
	}
}

func TestCustomCSPMiddleware(t *testing.T) {
	config := DefaultCSPConfig()
	config.ScriptSrc = append(config.ScriptSrc, "https://example.com")
	config.ReportURI = []string{"https://example.com/csp-report"}

	middleware := CSP(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	cspHeader := rr.Header().Get("Content-Security-Policy")

	if cspHeader == "" {
		t.Fatal("CSP header should be set")
	}

	expectedParts := []string{
		"script-src 'self' https://example.com",
		"report-uri https://example.com/csp-report",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspHeader, part) {
			t.Errorf("Expected CSP header to contain '%s', got: %s", part, cspHeader)
		}
	}
}

func TestCSPWithNonceMiddleware(t *testing.T) {
	config := DefaultCSPConfig()

	middleware := CSPWithNonce(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	cspHeader := rr.Header().Get("Content-Security-Policy")

	if cspHeader == "" {
		t.Fatal("CSP header should be set")
	}

	// Should contain nonce
	if !strings.Contains(cspHeader, "'nonce-") {
		t.Error("CSP header should contain nonce")
	}

	// Count nonce occurrences (should be 2: one for script-src, one for style-src)
	nonceCount := strings.Count(cspHeader, "'nonce-")
	if nonceCount != 2 {
		t.Errorf("Expected 2 nonce directives, got %d", nonceCount)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()
	nonce2 := generateNonce()

	if nonce1 == nonce2 {
		t.Error("generateNonce should generate unique nonces")
	}

	if len(nonce1) == 0 {
		t.Error("generateNonce should not return empty string")
	}

	if len(nonce2) == 0 {
		t.Error("generateNonce should not return empty string")
	}

	// Test that nonces are base64 encoded (no padding)
	if strings.Contains(nonce1, "=") {
		t.Error("Nonce should use base64 without padding")
	}
}

func TestBuildCSPString(t *testing.T) {
	tests := []struct {
		name     string
		config   *CSPConfig
		nonce    string
		expected []string
	}{
		{
			name: "basic config",
			config: &CSPConfig{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'", "https://example.com"},
				StyleSrc:   []string{"'self'", "'unsafe-inline'"},
			},
			nonce: "",
			expected: []string{
				"default-src 'self'",
				"script-src 'self' https://example.com",
				"style-src 'self' 'unsafe-inline'",
			},
		},
		{
			name: "with nonce",
			config: &CSPConfig{
				ScriptSrc: []string{"'self'"},
				StyleSrc:  []string{"'self'"},
			},
			nonce: "abc123",
			expected: []string{
				"script-src 'self' 'nonce-abc123'",
				"style-src 'self' 'nonce-abc123'",
			},
		},
		{
			name: "boolean directives",
			config: &CSPConfig{
				DefaultSrc:              []string{"'self'"},
				UpgradeInsecureRequests: true,
				BlockAllMixedContent:    true,
			},
			nonce: "",
			expected: []string{
				"default-src 'self'",
				"upgrade-insecure-requests",
				"block-all-mixed-content",
			},
		},
		{
			name: "reporting directives",
			config: &CSPConfig{
				DefaultSrc: []string{"'self'"},
				ReportURI:  []string{"https://example.com/csp-report"},
				ReportTo:   "csp-endpoint",
			},
			nonce: "",
			expected: []string{
				"default-src 'self'",
				"report-uri https://example.com/csp-report",
				"report-to csp-endpoint",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCSPString(tt.config, tt.nonce)

			for _, expected := range tt.expected {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected CSP string to contain '%s', got: %s", expected, result)
				}
			}
		})
	}
}

func TestComplexConfiguration(t *testing.T) {
	// Test a complex real-world scenario
	config := DefaultCSPConfig()

	// Add multiple script sources
	config.ScriptSrc = append(config.ScriptSrc,
		"https://cdnjs.cloudflare.com",
		"https://unpkg.com",
		"https://cdn.jsdelivr.net",
		"'sha256-abc123...'", // SRI hash
	)

	// Allow Google Fonts
	config.StyleSrc = append(config.StyleSrc, "https://fonts.googleapis.com")
	config.FontSrc = append(config.FontSrc, "https://fonts.gstatic.com")

	// Allow images from HTTPS and blob URLs
	config.ImgSrc = append(config.ImgSrc, "https:", "blob:")

	// API and WebSocket connections
	config.ConnectSrc = append(config.ConnectSrc,
		"https://api.example.com",
		"https://analytics.example.com",
		"wss://websocket.example.com",
	)

	// Allow embedding videos from YouTube
	config.MediaSrc = append(config.MediaSrc, "https://www.youtube.com")

	// Add SRI requirement
	config.RequireSriFor = []string{"script", "style"}

	// Add reporting
	config.ReportURI = []string{"https://example.com/csp-report"}

	// Test with middleware
	middleware := CSP(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	cspHeader := rr.Header().Get("Content-Security-Policy")

	expectedParts := []string{
		"https://cdnjs.cloudflare.com",
		"https://fonts.googleapis.com",
		"https://fonts.gstatic.com",
		"wss://websocket.example.com",
		"https://www.youtube.com",
		"require-sri-for script style",
		"report-uri https://example.com/csp-report",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspHeader, part) {
			t.Errorf("Expected CSP to contain '%s', got: %s", part, cspHeader)
		}
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Performance Benchmark Tests
func BenchmarkDefaultCSP(b *testing.B) {
	middleware := DefaultCSP()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rr.Header().Del("Content-Security-Policy") // Reset header
		middleware(handler).ServeHTTP(rr, req)
	}
}

func BenchmarkStrictCSP(b *testing.B) {
	middleware := StrictCSP()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rr.Header().Del("Content-Security-Policy") // Reset header
		middleware(handler).ServeHTTP(rr, req)
	}
}

func BenchmarkCustomCSP(b *testing.B) {
	config := DefaultCSPConfig()
	config.ScriptSrc = append(config.ScriptSrc, "https://example.com")
	middleware := CSP(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rr.Header().Del("Content-Security-Policy") // Reset header
		middleware(handler).ServeHTTP(rr, req)
	}
}

func BenchmarkCSPWithNonce(b *testing.B) {
	config := DefaultCSPConfig()
	middleware := CSPWithNonce(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rr.Header().Del("Content-Security-Policy") // Reset header
		middleware(handler).ServeHTTP(rr, req)
	}
}

func BenchmarkDefaultCSPConfig(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config := DefaultCSPConfig()
		_ = config // Prevent optimization
	}
}

func BenchmarkBuildCSPString(b *testing.B) {
	config := DefaultCSPConfig()
	config.ScriptSrc = append(config.ScriptSrc, "https://example.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := buildCSPString(config, "")
		_ = result // Prevent optimization
	}
}

func BenchmarkBuildCSPStringWithNonce(b *testing.B) {
	config := DefaultCSPConfig()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		nonce := generateNonce()
		result := buildCSPString(config, nonce)
		_ = result // Prevent optimization
	}
}

func BenchmarkGenerateNonce(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		nonce := generateNonce()
		_ = nonce // Prevent optimization
	}
}

func BenchmarkDefaultCSPHeaderOnly(b *testing.B) {
	rw := &testResponseWriter{header: make(http.Header)}

	str := []string{defaultCSPString}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rw.header["Content-Security-Policy"] = str
	}
}

func BenchmarkDefaultCSPComplete(b *testing.B) {
	middleware := DefaultCSP()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	rw := &testResponseWriter{header: make(http.Header)}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rw.header.Del("Content-Security-Policy")
		middleware(handler).ServeHTTP(rw, req)
	}
}

// Minimal ResponseWriter for benchmarking
type testResponseWriter struct {
	header http.Header
}

func (w *testResponseWriter) Header() http.Header {
	return w.header
}

func (w *testResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (w *testResponseWriter) WriteHeader(statusCode int) {}

func BenchmarkHttpHeaderMapOperation(b *testing.B) {
	header := make(http.Header)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		header.Set("Content-Security-Policy", defaultCSPString)
	}
}

func BenchmarkHttpHeaderMapOperationWithDel(b *testing.B) {
	header := make(http.Header)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		header.Del("Content-Security-Policy")
		header.Set("Content-Security-Policy", defaultCSPString)
	}
}
