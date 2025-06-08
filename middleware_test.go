package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenBucketLimiter(t *testing.T) {
	h := TokenBucketLimiter(1, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 got %d", rec.Code)
	}
}

func TestFixedWindowLimiter(t *testing.T) {
	h := FixedWindowLimiter(1, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 got %d", rec.Code)
	}
}

func TestCORS(t *testing.T) {
	h := CORSMiddleware(Options{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-CSRF-Token"},
		AllowCredentials: true,
		Debug:            false,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("missing cors header")
	}
}

func TestLogging(t *testing.T) {
	buf := bytes.Buffer{}
	logger := log.New(&buf, "", 0)
	h := LoggingMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected 418 got %d", rec.Code)
	}
	if !strings.Contains(buf.String(), "418") {
		t.Fatalf("logger did not record status")
	}
}
