package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// Middleware defines a function that wraps an http.Handler
type Middleware func(http.HandlerFunc) http.HandlerFunc

// Chain creates a new middleware chain, executing them in the order they are passed
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		// Start from the last middleware and work backwards
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// WithContext adds a context value to the request
func WithContext(key, value interface{}) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), key, value)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Skipper defines a function to skip middleware.
type Skipper func(r *http.Request) bool

// DefaultSkipper is a no-op skipper.
var DefaultSkipper Skipper = func(r *http.Request) bool { return false }

func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	// Remove 0, O, 1, I to remove ambiguity
	code := base64.RawURLEncoding.EncodeToString(bytes)
	return code, nil
}

func EncodeBase64UrlNoPadding(data []byte) string {
	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}

func DecodeBase64UrlNoPadding(data string) ([]byte, error) {
	return base64.RawURLEncoding.WithPadding(base64.NoPadding).DecodeString(data)
}

// statusRecorder wraps ResponseWriter to capture status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
