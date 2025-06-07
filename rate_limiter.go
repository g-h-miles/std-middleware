package middleware

import (
	"net/http"
	"sync"
	"time"
)

// TokenBucketLimiter returns a middleware that limits requests using a token bucket.
func TokenBucketLimiter(capacity int, refill time.Duration) func(http.Handler) http.Handler {
	tokens := make(chan struct{}, capacity)
	for i := 0; i < capacity; i++ {
		tokens <- struct{}{}
	}
	go func() {
		ticker := time.NewTicker(refill)
		defer ticker.Stop()
		for range ticker.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-tokens:
				next.ServeHTTP(w, r)
			default:
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			}
		})
	}
}

// FixedWindowLimiter returns a middleware that limits requests per interval.
func FixedWindowLimiter(limit int, interval time.Duration) func(http.Handler) http.Handler {
	var mu sync.Mutex
	count := 0
	reset := time.Now().Add(interval)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			now := time.Now()
			if now.After(reset) {
				count = 0
				reset = now.Add(interval)
			}
			if count >= limit {
				mu.Unlock()
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			count++
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}
