package middleware

import (
	"net/http"
)

type CSRFConfig struct {
	Skipper     Skipper
	TokenLength int
	CookieName  string
	HeaderName  string
}

// CSRFMiddleware returns a middleware implementing a simple CSRF protection.
func CSRFMiddleware() func(http.Handler) http.Handler {
	cfg := CSRFConfig{
		TokenLength: 32,
		CookieName:  "csrf_token",
		HeaderName:  "X-CSRF-Token",
	}
	return CSRFMiddlewareWithConfig(cfg)
}

// CSRFMiddlewareWithConfig allows custom configuration.
func CSRFMiddlewareWithConfig(cfg CSRFConfig) func(http.Handler) http.Handler {
	if cfg.Skipper == nil {
		cfg.Skipper = DefaultSkipper
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Skipper(r) {
				next.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil || cookie.Value == "" {
				token := randomString(cfg.TokenLength)
				http.SetCookie(w, &http.Cookie{Name: cfg.CookieName, Value: token, Path: "/", HttpOnly: true})
				cookie = &http.Cookie{Value: token}
			}
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get(cfg.HeaderName) != cookie.Value {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
