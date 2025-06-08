package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"time"
)

type CSRFConfig struct {
	Secret            []byte
	TokenLength       int
	CookieName        string
	HeaderName        string
	UseSession        bool
	SessionCookieName string
	Secure            bool
	SameSite          http.SameSite
	MaxAge            time.Duration
	Skipper           Skipper

	once          sync.Once
	validationErr error
}

func defaultSkipper(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
}

func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		Secret:            nil,
		TokenLength:       32,
		CookieName:        "csrf_token",
		HeaderName:        "X-CSRF-Token",
		UseSession:        false,
		SessionCookieName: "session_token",
		Secure:            false,
		SameSite:          http.SameSiteLaxMode,
		MaxAge:            3600 * time.Second,
		Skipper:           defaultSkipper,
	}
}

func (cfg *CSRFConfig) Middleware() Middleware {
	cfg.validateConfig()

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Skipper(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ===== CSRF COOKIE ======
			csrfCookie, err := r.Cookie(cfg.CookieName)
			if err != nil || csrfCookie.Value == "" {
				http.Error(w, "CSRF token required", http.StatusForbidden)
				return
			}

			// ===== CSRF HEADER ======
			csrfHeaders := r.Header[cfg.HeaderName]
			var csrfHeader string

			if len(csrfHeaders) == 0 {
				http.Error(w, "CSRF token required", http.StatusForbidden)
				return
			}
			csrfHeader = csrfHeaders[0]
			if csrfHeader == "" {
				http.Error(w, "CSRF token required", http.StatusForbidden)
				return
			}

			if cfg.UseSession {
				// ===== SESSION COOKIE ======
				sessionCookie, err := r.Cookie(cfg.SessionCookieName)
				if err != nil {
					http.Error(w, "Invalid session", http.StatusUnauthorized)
					return
				}
				if sessionCookie.Value == "" {
					http.Error(w, "Invalid session", http.StatusUnauthorized)
					return
				}

				// ===== VERIFY TOKEN ======
				verified, err := cfg.verifyCSRFToken(csrfHeader, sessionCookie.Value, csrfCookie.Value)
				if err != nil {
					http.Error(w, "Invalid CSRF token", http.StatusForbidden)
					return
				}
				if !verified {
					http.Error(w, "Invalid CSRF token", http.StatusForbidden)
					return
				}
			} else {
				// ===== SIMPLE COMPARISON ======
				if csrfCookie.Value != csrfHeader {
					http.Error(w, "Invalid CSRF token", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (cfg *CSRFConfig) verifyCSRFToken(token string, sessionToken string, storedHMAC string) (bool, error) {
	decodedHMAC, err := DecodeBase64UrlNoPadding(storedHMAC)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha256.New, cfg.Secret)
	mac.Write([]byte(token + "." + sessionToken))
	expectedHMAC := mac.Sum(nil)
	return hmac.Equal(decodedHMAC, expectedHMAC), nil
}

func (cfg *CSRFConfig) GenerateCSRFToken(sessionToken string) (string, string, error) {
	cfg.validateConfig()
	csrfToken, err := GenerateRandomString(cfg.TokenLength)
	if err != nil {
		return "", "", err
	}
	if !cfg.UseSession {
		return csrfToken, "", nil
	}
	if sessionToken == "" {
		return "", "", errors.New("session token is required")
	}

	mac := hmac.New(sha256.New, cfg.Secret)
	mac.Write([]byte(csrfToken + "." + sessionToken))
	csrfTokenHMAC := mac.Sum(nil)
	return csrfToken, EncodeBase64UrlNoPadding(csrfTokenHMAC), nil
}

func (cfg *CSRFConfig) SetCSRFToken(w http.ResponseWriter, r *http.Request) error {
	cfg.validateConfig()

	sessionValue := ""
	if cfg.UseSession {
		sessionCookie, err := r.Cookie(cfg.SessionCookieName)
		if err != nil {
			return err // No session cookie at all
		}
		sessionValue = sessionCookie.Value
		// Empty sessionValue will be caught by GenerateCSRFToken
	}
	token, encodedHMAC, err := cfg.GenerateCSRFToken(sessionValue)

	if err != nil {
		return err
	}

	var cookieValue string
	if cfg.UseSession {
		cookieValue = encodedHMAC
	} else {
		cookieValue = token
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   int(cfg.MaxAge.Seconds()),
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})
	// Return the token to be used in the X-CSRF-Token header
	w.Header()[cfg.HeaderName] = []string{token}
	return nil
}

func (cfg *CSRFConfig) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := cfg.SetCSRFToken(w, r); err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Session required", http.StatusUnauthorized)
			} else {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			}
			return
		}

		w.Header()["Content-Type"] = []string{"application/json"}
		w.Write([]byte(`{"status":"token_set"}`))
	}
}

func (cfg *CSRFConfig) validateConfig() {
	cfg.once.Do(func() {
		// All validation logic moved here
		if cfg.UseSession && len(cfg.Secret) == 0 {
			cfg.validationErr = errors.New("CSRF: secret is required when UseSession is true")
			return
		}
		if cfg.UseSession && cfg.SessionCookieName == "" {
			cfg.validationErr = errors.New("CSRF: session cookie name is required when UseSession is true")
			return
		}
		if cfg.UseSession && cfg.CookieName == cfg.SessionCookieName {
			cfg.validationErr = errors.New("CSRF: cookie name and session cookie name cannot be the same")
			return
		}
		if cfg.CookieName == "" {
			cfg.validationErr = errors.New("CSRF: cookie name is required")
			return
		}
		if cfg.HeaderName == "" {
			cfg.validationErr = errors.New("CSRF: header name is required")
			return
		}
		if cfg.MaxAge <= 0 {
			cfg.validationErr = errors.New("CSRF: max age must be positive")
			return
		}
		if cfg.TokenLength <= 15 {
			cfg.validationErr = errors.New("CSRF: token length must be greater than 15")
			return
		}
		// No error - validation passed
	})

	if cfg.validationErr != nil {
		panic(cfg.validationErr)
	}

}
