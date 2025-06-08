package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultCSRFConfig(t *testing.T) {
	cfg := DefaultCSRFConfig()

	if cfg.TokenLength != 32 {
		t.Errorf("Expected TokenLength 32, got %d", cfg.TokenLength)
	}
	if cfg.CookieName != "csrf_token" {
		t.Errorf("Expected CookieName 'csrf_token', got %s", cfg.CookieName)
	}
	if cfg.HeaderName != "X-CSRF-Token" {
		t.Errorf("Expected HeaderName 'X-CSRF-Token', got %s", cfg.HeaderName)
	}
	if cfg.UseSession != false {
		t.Errorf("Expected UseSession false, got %t", cfg.UseSession)
	}
	if cfg.MaxAge != 3600*time.Second {
		t.Errorf("Expected MaxAge 3600s, got %v", cfg.MaxAge)
	}
}

func TestValidateConfig_ValidConfigs(t *testing.T) {
	tests := []struct {
		name   string
		config *CSRFConfig
	}{
		{
			name:   "Simple mode valid",
			config: DefaultCSRFConfig(),
		},
		{
			name: "Session mode valid",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.UseSession = true
				cfg.Secret = []byte("test-secret")
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("validateConfig panicked: %v", r)
				}
			}()
			tt.config.validateConfig()
		})
	}
}

func TestValidateConfig_InvalidConfigs(t *testing.T) {
	tests := []struct {
		name        string
		config      *CSRFConfig
		expectedMsg string
	}{
		{
			name: "UseSession true but no secret",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.UseSession = true
				return cfg
			}(),
			expectedMsg: "secret is required when UseSession is true",
		},
		{
			name: "UseSession true but empty secret",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.UseSession = true
				cfg.Secret = []byte{}
				return cfg
			}(),
			expectedMsg: "secret is required when UseSession is true",
		},
		{
			name: "UseSession true but no session cookie name",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.UseSession = true
				cfg.Secret = []byte("secret")
				cfg.SessionCookieName = ""
				return cfg
			}(),
			expectedMsg: "session cookie name is required when UseSession is true",
		},
		{
			name: "Same cookie names when using session",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.UseSession = true
				cfg.Secret = []byte("secret")
				cfg.CookieName = "same_name"
				cfg.SessionCookieName = "same_name"
				return cfg
			}(),
			expectedMsg: "cookie name and session cookie name cannot be the same",
		},
		{
			name: "Empty cookie name",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.CookieName = ""
				return cfg
			}(),
			expectedMsg: "cookie name is required",
		},
		{
			name: "Empty header name",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.HeaderName = ""
				return cfg
			}(),
			expectedMsg: "header name is required",
		},
		{
			name: "Zero max age",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.MaxAge = 0
				return cfg
			}(),
			expectedMsg: "max age must be positive",
		},
		{
			name: "Token length too short",
			config: func() *CSRFConfig {
				cfg := DefaultCSRFConfig()
				cfg.TokenLength = 15
				return cfg
			}(),
			expectedMsg: "token length must be greater than 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !strings.Contains(r.(error).Error(), tt.expectedMsg) {
						t.Errorf("Expected panic message to contain %q, got %v", tt.expectedMsg, r)
					}
				} else {
					t.Error("Expected validateConfig to panic")
				}
			}()
			tt.config.validateConfig()
		})
	}
}

func TestValidateConfig_OnlyOnce(t *testing.T) {
	cfg := DefaultCSRFConfig()

	// Call multiple times - should not panic after first call
	cfg.validateConfig()
	cfg.validateConfig()
	cfg.validateConfig()

	// Test thread safety
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg.validateConfig()
		}()
	}
	wg.Wait()
}

func TestGenerateCSRFToken_SimpleMode(t *testing.T) {
	cfg := DefaultCSRFConfig()

	token, hmac, err := cfg.GenerateCSRFToken("")
	if err != nil {
		t.Fatalf("GenerateCSRFToken failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}
	if hmac != "" {
		t.Error("Expected empty HMAC in simple mode")
	}
	if len(token) == 0 {
		t.Error("Expected token to have content")
	}
}

func TestGenerateCSRFToken_SessionMode(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	token, hmac, err := cfg.GenerateCSRFToken("session-123")
	if err != nil {
		t.Fatalf("GenerateCSRFToken failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}
	if hmac == "" {
		t.Error("Expected non-empty HMAC in session mode")
	}
}

func TestGenerateCSRFToken_SessionMode_EmptySession(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	_, _, err := cfg.GenerateCSRFToken("")
	if err == nil {
		t.Error("Expected error for empty session token")
	}
	if !strings.Contains(err.Error(), "session token is required") {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestSetCSRFToken_SimpleMode(t *testing.T) {
	cfg := DefaultCSRFConfig()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	err := cfg.SetCSRFToken(w, r)
	if err != nil {
		t.Fatalf("SetCSRFToken failed: %v", err)
	}

	// Check cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == cfg.CookieName {
			found = true
			if cookie.Value == "" {
				t.Error("Expected non-empty cookie value")
			}
		}
	}
	if !found {
		t.Error("Expected CSRF cookie to be set")
	}

	// Check header was set
	headerValue := w.Header()[cfg.HeaderName][0]
	if headerValue == "" {
		t.Error("Expected CSRF header to be set")
	}
}

func TestSetCSRFToken_SessionMode(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: "session-123",
	})

	err := cfg.SetCSRFToken(w, r)
	if err != nil {
		t.Fatalf("SetCSRFToken failed: %v", err)
	}

	// Check cookie and header are different (HMAC vs token)
	var cookieValue string
	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == cfg.CookieName {
			cookieValue = cookie.Value
		}
	}

	headerValue := w.Header()[cfg.HeaderName][0]
	if cookieValue == headerValue {
		t.Error("In session mode, cookie and header should be different")
	}
}

func TestSetCSRFToken_SessionMode_NoSession(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	// No session cookie

	err := cfg.SetCSRFToken(w, r)
	if err == nil {
		t.Error("Expected error when no session cookie")
	}
}

func TestTokenHandler_Success(t *testing.T) {
	cfg := DefaultCSRFConfig()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/csrf-token", nil)

	handler := cfg.TokenHandler()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response["status"] != "token_set" {
		t.Errorf("Expected status 'token_set', got %s", response["status"])
	}
}

func TestTokenHandler_SessionRequired(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/csrf-token", nil)
	// No session cookie

	handler := cfg.TokenHandler()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMiddleware_SimpleMode_ValidRequest(t *testing.T) {
	cfg := DefaultCSRFConfig()

	// Generate a token first
	token, _, err := cfg.GenerateCSRFToken("")
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test", nil)
	r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	r.Header[cfg.HeaderName] = []string{token}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("Expected next handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestMiddleware_SimpleMode_InvalidToken(t *testing.T) {
	cfg := DefaultCSRFConfig()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test", nil)
	r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: "token1"})
	r.Header[cfg.HeaderName] = []string{"token2"} // Different token

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if called {
		t.Error("Expected next handler NOT to be called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestMiddleware_SessionMode_ValidRequest(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	sessionToken := "session-123"
	csrfToken, hmac, err := cfg.GenerateCSRFToken(sessionToken)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test", nil)
	r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: hmac})
	r.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sessionToken})
	r.Header[cfg.HeaderName] = []string{csrfToken}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("Expected next handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestMiddleware_SkipSafeMethods(t *testing.T) {
	cfg := DefaultCSRFConfig()

	methods := []string{"GET", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/api/test", nil)
			// No CSRF tokens provided

			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			})

			middleware := cfg.Middleware()
			handler := middleware(next)
			handler.ServeHTTP(w, r)

			if !called {
				t.Error("Expected next handler to be called for safe method")
			}
		})
	}
}

func TestMiddleware_MissingCookie(t *testing.T) {
	cfg := DefaultCSRFConfig()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test", nil)
	// No cookie, but header present
	r.Header[cfg.HeaderName] = []string{"some-token"}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if called {
		t.Error("Expected next handler NOT to be called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestMiddleware_MissingHeader(t *testing.T) {
	cfg := DefaultCSRFConfig()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test", nil)
	r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: "some-token"})
	// No header

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if called {
		t.Error("Expected next handler NOT to be called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestVerifyCSRFToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	sessionToken := "session-123"
	csrfToken, hmac, err := cfg.GenerateCSRFToken(sessionToken)
	if err != nil {
		t.Fatal(err)
	}

	// Valid verification
	valid, err := cfg.verifyCSRFToken(csrfToken, sessionToken, hmac)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected token to be valid")
	}

	// Invalid session token
	valid, err = cfg.verifyCSRFToken(hmac, "wrong-session", csrfToken)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected token to be invalid with wrong session")
	}

	// Invalid CSRF token
	valid, err = cfg.verifyCSRFToken(hmac, sessionToken, "wrong-csrf")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected token to be invalid with wrong CSRF token")
	}
}

func TestCustomSkipper(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.Skipper = func(r *http.Request) bool {
		return r.URL.Path == "/skip-csrf"
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/skip-csrf", nil)
	// No CSRF tokens

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	middleware := cfg.Middleware()
	handler := middleware(next)
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("Expected next handler to be called due to custom skipper")
	}
}

// Benchmark tests
func BenchmarkValidateConfig(b *testing.B) {
	cfg := DefaultCSRFConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.validateConfig()
	}
}

func BenchmarkGenerateCSRFToken_Simple(b *testing.B) {
	cfg := DefaultCSRFConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.GenerateCSRFToken("")
	}
}

func BenchmarkGenerateCSRFToken_Session(b *testing.B) {
	cfg := DefaultCSRFConfig()
	cfg.UseSession = true
	cfg.Secret = []byte("test-secret")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.GenerateCSRFToken("session-123")
	}
}

func BenchmarkMiddleware_SimpleMode(b *testing.B) {
	cfg := DefaultCSRFConfig()
	token, _, _ := cfg.GenerateCSRFToken("") // Generate token once

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	middleware := cfg.Middleware()
	handler := middleware(next)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/test", nil)
		r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token}) // <-- Allocations here
		r.Header[cfg.HeaderName] = []string{token}                    // <-- Allocations here

		handler.ServeHTTP(w, r)
	}
}
