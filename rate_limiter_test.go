package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Helper for Rate Limiter Tests ---

// CapturingResponseWriter captures status code and body for assertions
type CapturingResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	Body       *bytes.Buffer
}

func NewCapturingResponseWriter() *CapturingResponseWriter {
	return &CapturingResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		StatusCode:     http.StatusOK,
		Body:           new(bytes.Buffer),
	}
}

func (c *CapturingResponseWriter) WriteHeader(statusCode int) {
	c.StatusCode = statusCode
	c.ResponseWriter.WriteHeader(statusCode)
}

func (c *CapturingResponseWriter) Write(b []byte) (int, error) {
	c.Body.Write(b)
	return c.ResponseWriter.Write(b)
}

// --- Token Bucket Rate Limiter Tests ---

func TestNewTokenBucketRateLimiter(t *testing.T) {
	_, err := NewTokenBucketRateLimiter("test", 10, 1.0)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = NewTokenBucketRateLimiter("test", 0, 1.0)
	if err == nil || !strings.Contains(err.Error(), "capacity must be positive") {
		t.Errorf("Expected capacity error, got %v", err)
	}

	_, err = NewTokenBucketRateLimiter("test", 10, 0)
	if err == nil || !strings.Contains(err.Error(), "refill rate must be positive") {
		t.Errorf("Expected refill rate error, got %v", err)
	}
}

func TestTokenBucket_IsAllowed(t *testing.T) {
	// Capacity 5, refills 1 token per second
	limiter, _ := NewTokenBucketRateLimiter("test_tb_allowed", 5, 1.0)
	key := "user_1"

	// 1. Initial requests (should be allowed up to capacity)
	for i := 0; i < 5; i++ {
		if !limiter.IsAllowed(key) {
			t.Fatalf("Expected request %d to be allowed initially", i+1)
		}
	}

	// 2. Sixth request (should be denied immediately)
	if limiter.IsAllowed(key) {
		t.Error("Expected 6th request to be denied immediately")
	}

	// 3. Wait for 1 second, then 1 token should be refilled
	time.Sleep(time.Second + (time.Millisecond * 100)) // Add a small buffer
	if !limiter.IsAllowed(key) {
		t.Error("Expected request to be allowed after 1 second refill")
	}
	if limiter.IsAllowed(key) {
		t.Error("Expected immediate subsequent request to be denied")
	}

	// 4. Wait for 5 seconds to refill to full capacity
	time.Sleep(time.Second * 5)
	for i := 0; i < 5; i++ {
		if !limiter.IsAllowed(key) {
			t.Fatalf("Expected request %d to be allowed after full refill", i+1)
		}
	}
}

func TestTokenBucketMiddleware(t *testing.T) {
	// Capacity 1, refills 1 token per hour (effectively 1 allowed then denied)
	limiter, _ := NewTokenBucketRateLimiter("test_tb_middleware", 1, 1.0/3600.0)
	mw := TokenBucketMiddleware(limiter, "Rate Limit Exceeded", http.StatusForbidden)

	// Mock next handler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Allowed"))
	})

	handler := mw(next)

	// 1. First request (allowed)
	w1 := NewCapturingResponseWriter()
	r1 := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w1, r1)
	if w1.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w1.StatusCode)
	}
	if w1.Body.String() != "Allowed" {
		t.Errorf("Expected body 'Allowed', got %s", w1.Body.String())
	}

	// 2. Second request (denied)
	w2 := NewCapturingResponseWriter()
	r2 := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w2, r2)
	if w2.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status Forbidden, got %d", w2.StatusCode)
	}
	if w2.Body.String() != "Rate Limit Exceeded\n" { // http.Error adds a newline
		t.Errorf("Expected body 'Rate Limit Exceeded', got %s", w2.Body.String())
	}
}

func TestTokenBucketMiddleware_PanicOnNilLimiter(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil limiter")
		}
	}()
	TokenBucketMiddleware(nil, "", 0)
}

// --- Fixed Window Rate Limiter Tests ---

func TestNewFixedWindowRateLimiter(t *testing.T) {
	_, err := NewFixedWindowRateLimiter("test", 10, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = NewFixedWindowRateLimiter("test", 0, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "limit must be positive") {
		t.Errorf("Expected limit error, got %v", err)
	}

	_, err = NewFixedWindowRateLimiter("test", 10, 0)
	if err == nil || !strings.Contains(err.Error(), "window size must be positive") {
		t.Errorf("Expected window size error, got %v", err)
	}
}

func TestFixedWindow_IsAllowed(t *testing.T) {
	// Capacity 2, refills 1 token per 1-second window
	// Use a slightly longer window for test robustness, e.g., 500ms
	windowDuration := 500 * time.Millisecond // Shorter window for faster test
	limiter, _ := NewFixedWindowRateLimiter("test_fw_allowed", 2, windowDuration)
	key := "user_2"

	// 1. Initial requests (should be allowed up to limit)
	if !limiter.IsAllowed(key) { // 1st allowed
		t.Fatalf("Expected request 1 to be allowed")
	}
	if !limiter.IsAllowed(key) { // 2nd allowed
		t.Fatalf("Expected request 2 to be allowed")
	}

	// 2. Third request (should be denied immediately)
	if limiter.IsAllowed(key) {
		t.Error("Expected 3rd request to be denied immediately")
	}

	// 3. Wait for window to reset
	// Sleep for (windowDuration + a small buffer)
	// Example: time.Sleep(windowDuration + (50 * time.Millisecond))
	time.Sleep(windowDuration + (windowDuration / 2)) // Sleep 1.5 times the window to be sure

	// Expected to be allowed after window reset
	if !limiter.IsAllowed(key) {
		t.Error("Expected request to be allowed after window reset")
	}
}

func TestFixedWindowMiddleware(t *testing.T) {
	// Limit 1 request per 1-second window
	limiter, _ := NewFixedWindowRateLimiter("test_fw_middleware", 1, time.Second)
	mw := FixedWindowMiddleware(limiter, "Fixed Window Limit Hit", http.StatusConflict) // Custom error/status

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Allowed by Fixed Window"))
	})

	handler := mw(next)

	// 1. First request (allowed)
	w1 := NewCapturingResponseWriter()
	r1 := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w1, r1)
	if w1.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w1.StatusCode)
	}
	if w1.Body.String() != "Allowed by Fixed Window" {
		t.Errorf("Expected body 'Allowed by Fixed Window', got %s", w1.Body.String())
	}

	// 2. Second request (denied within same window)
	w2 := NewCapturingResponseWriter()
	r2 := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w2, r2)
	if w2.StatusCode != http.StatusConflict {
		t.Errorf("Expected status Conflict, got %d", w2.StatusCode)
	}
	if w2.Body.String() != "Fixed Window Limit Hit\n" {
		t.Errorf("Expected body 'Fixed Window Limit Hit', got %s", w2.Body.String())
	}
}

func TestFixedWindowMiddleware_PanicOnNilLimiter(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil limiter")
		}
	}()
	FixedWindowMiddleware(nil, "", 0)
}

// --- Concurrent Rate Limiter Benchmarks ---

func BenchmarkTokenBucket_IsAllowed_Concurrent(b *testing.B) {
	limiter, _ := NewTokenBucketRateLimiter("bench_tb_isallowed", b.N, float64(b.N)/float64(b.N)) // High capacity & refill
	key := "bench_user"

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.IsAllowed(key)
		}
	})
}

func BenchmarkTokenBucketMiddleware_Concurrent(b *testing.B) {
	limiter, _ := NewTokenBucketRateLimiter("bench_tb_middleware", b.N, float64(b.N)/float64(b.N))
	mw := TokenBucketMiddleware(limiter, "", 0)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := mw(next)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder() // Each goroutine gets its own recorder
		// Reuse requests (still some allocations per request)
		r := httptest.NewRequest("GET", "/", nil) // Only GET to avoid Middleware's method checks
		for pb.Next() {
			handler.ServeHTTP(w, r)
		}
	})
}

func BenchmarkFixedWindow_IsAllowed_Concurrent(b *testing.B) {
	limiter, _ := NewFixedWindowRateLimiter("bench_fw_isallowed", b.N, time.Hour) // High limit, long window
	key := "bench_user"

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.IsAllowed(key)
		}
	})
}

func BenchmarkFixedWindowMiddleware_Concurrent(b *testing.B) {
	limiter, _ := NewFixedWindowRateLimiter("bench_fw_middleware", b.N, time.Hour)
	mw := FixedWindowMiddleware(limiter, "", 0)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := mw(next)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder()               // Each goroutine gets its own recorder
		r := httptest.NewRequest("GET", "/", nil) // Only GET to avoid Middleware's method checks
		for pb.Next() {
			handler.ServeHTTP(w, r)
		}
	})
}
