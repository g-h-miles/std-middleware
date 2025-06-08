package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
)

// CSPConfig represents a Content Security Policy configuration
type CSPConfig struct {
	DefaultSrc              []string
	ScriptSrc               []string
	StyleSrc                []string
	ImgSrc                  []string
	ConnectSrc              []string
	FontSrc                 []string
	ObjectSrc               []string
	MediaSrc                []string
	FrameSrc                []string
	WorkerSrc               []string
	ManifestSrc             []string
	BaseURI                 []string
	FormAction              []string
	FrameAncestors          []string
	ReportURI               []string
	ReportTo                string
	UpgradeInsecureRequests bool
	BlockAllMixedContent    bool
	RequireSriFor           []string
}

// Pre-computed strings for maximum performance
const (
	defaultCSPString = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; media-src 'self'; frame-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content"

	strictCSPString = "default-src 'none'; script-src 'self' 'strict-dynamic'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none'; worker-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
)

// String pool for building CSP headers
var stringBuilderPool = sync.Pool{
	New: func() interface{} {
		sb := &strings.Builder{}
		sb.Grow(512) // Pre-allocate reasonable size
		return sb
	},
}

// Nonce pool for reusing byte arrays
var noncePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 16)
		return &b
	},
}

// Ultra-fast nonce generation
func generateNonce() string {
	bytesPtr := noncePool.Get().(*[]byte)
	defer noncePool.Put(bytesPtr)
	bytes := *bytesPtr
	rand.Read(bytes)
	return base64.RawStdEncoding.EncodeToString(bytes[:])
}

// Fast CSP string builder
func buildCSPString(config *CSPConfig, nonce string) string {
	sb := stringBuilderPool.Get().(*strings.Builder)
	defer func() {
		sb.Reset()
		stringBuilderPool.Put(sb)
	}()

	addDir := func(name string, values []string) {
		if len(values) > 0 {
			if sb.Len() > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(name)
			sb.WriteByte(' ')
			for i, v := range values {
				if i > 0 {
					sb.WriteByte(' ')
				}
				sb.WriteString(v)
			}
		}
	}

	// Add nonce to script and style if provided
	scriptSrc := config.ScriptSrc
	styleSrc := config.StyleSrc
	if nonce != "" {
		nonceDirective := "'nonce-" + nonce + "'"
		if len(scriptSrc) > 0 {
			scriptSrc = append(append([]string(nil), scriptSrc...), nonceDirective)
		}
		if len(styleSrc) > 0 {
			styleSrc = append(append([]string(nil), styleSrc...), nonceDirective)
		}
	}

	addDir("default-src", config.DefaultSrc)
	addDir("script-src", scriptSrc)
	addDir("style-src", styleSrc)
	addDir("img-src", config.ImgSrc)
	addDir("connect-src", config.ConnectSrc)
	addDir("font-src", config.FontSrc)
	addDir("object-src", config.ObjectSrc)
	addDir("media-src", config.MediaSrc)
	addDir("frame-src", config.FrameSrc)
	addDir("worker-src", config.WorkerSrc)
	addDir("manifest-src", config.ManifestSrc)
	addDir("base-uri", config.BaseURI)
	addDir("form-action", config.FormAction)
	addDir("frame-ancestors", config.FrameAncestors)
	addDir("report-uri", config.ReportURI)

	if config.ReportTo != "" {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString("report-to ")
		sb.WriteString(config.ReportTo)
	}

	if config.UpgradeInsecureRequests {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString("upgrade-insecure-requests")
	}

	if config.BlockAllMixedContent {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString("block-all-mixed-content")
	}

	addDir("require-sri-for", config.RequireSriFor)

	return sb.String()
}

// DefaultCSPConfig returns a new default configuration that users can modify
func DefaultCSPConfig() *CSPConfig {
	return &CSPConfig{
		DefaultSrc:              []string{"'self'"},
		ScriptSrc:               []string{"'self'"},
		StyleSrc:                []string{"'self'", "'unsafe-inline'"},
		ImgSrc:                  []string{"'self'", "data:"},
		ConnectSrc:              []string{"'self'"},
		FontSrc:                 []string{"'self'", "data:"},
		ObjectSrc:               []string{"'none'"},
		MediaSrc:                []string{"'self'"},
		FrameSrc:                []string{"'self'"},
		WorkerSrc:               []string{"'self'"},
		ManifestSrc:             []string{"'self'"},
		BaseURI:                 []string{"'self'"},
		FormAction:              []string{"'self'"},
		FrameAncestors:          []string{"'none'"},
		UpgradeInsecureRequests: true,
		BlockAllMixedContent:    true,
	}
}

// StrictCSPConfig returns a new strict configuration that users can modify
func StrictCSPConfig() *CSPConfig {
	return &CSPConfig{
		DefaultSrc:              []string{"'none'"},
		ScriptSrc:               []string{"'self'", "'strict-dynamic'"},
		StyleSrc:                []string{"'self'"},
		ImgSrc:                  []string{"'self'", "data:"},
		ConnectSrc:              []string{"'self'"},
		FontSrc:                 []string{"'self'"},
		ObjectSrc:               []string{"'none'"},
		MediaSrc:                []string{"'self'"},
		FrameSrc:                []string{"'none'"},
		WorkerSrc:               []string{"'self'"},
		ManifestSrc:             []string{"'self'"},
		BaseURI:                 []string{"'self'"},
		FormAction:              []string{"'self'"},
		FrameAncestors:          []string{"'none'"},
		UpgradeInsecureRequests: true,
		BlockAllMixedContent:    true,
		RequireSriFor:           []string{"script", "style"},
	}
}

// FASTEST - Use pre-computed string (zero allocations)
func DefaultCSP() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", defaultCSPString)
			next.ServeHTTP(w, r)
		})
	}
}

// FASTEST - Use pre-computed strict string (zero allocations)
func StrictCSP() Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Security-Policy"] = []string{strictCSPString}
			next.ServeHTTP(w, r)
		})
	}
}

// FAST - Custom configuration (builds string once, reuses it)
func CSP(config *CSPConfig) Middleware {
	policy := buildCSPString(config, "")
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Security-Policy"] = []string{policy}
			next.ServeHTTP(w, r)
		})
	}
}

// FAST - With nonce generation (builds string per request with nonce)
func CSPWithNonce(config *CSPConfig) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := generateNonce()
			policy := buildCSPString(config, nonce)
			w.Header()["Content-Security-Policy"] = []string{policy}
			next.ServeHTTP(w, r)
		})
	}
}
