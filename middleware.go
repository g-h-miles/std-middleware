package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
)

// Skipper defines a function to skip middleware.
type Skipper func(r *http.Request) bool

// DefaultSkipper is a no-op skipper.
var DefaultSkipper Skipper = func(r *http.Request) bool { return false }

// randomString returns a random base64 string of n bytes.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(b)
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
