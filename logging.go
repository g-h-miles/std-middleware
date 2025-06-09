package middleware

import (
	"log"
	"net/http"
	"time"
)

// LoggingMiddleware logs request method, path and status code.
func LoggingMiddleware(logger *log.Logger) Middleware {
	if logger == nil {
		logger = log.Default()
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rec, r)
			logger.Printf("%s %s %d %v", r.Method, r.URL.Path, rec.status, time.Since(start))
		}
	}
}
