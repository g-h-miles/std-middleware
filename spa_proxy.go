// middleware/spa.go
package middleware

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path" // Use 'path' for virtual FS paths, not 'filepath'
	"strings"
)

type SPAConfig struct {
	// The filesystem containing your built frontend assets.
	// Must be populated with a //go:embed directive.
	DistFS embed.FS

	// The path within the embed.FS to the built assets.
	// Example: "frontend/dist"
	DistPath string

	// The name of the index file, defaults to "index.html".
	IndexFile string

	// --- Optional fields with sensible defaults ---
	DevProxyURL string

	Skipper Skipper

	IsDevMode bool
}

func defaultSPASkipper(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api")
}

// NewSPAHandler creates a new handler for a Single Page Application.
// It returns an error if the configuration is invalid for production mode.
func SPA(config SPAConfig) Middleware {
	if config.Skipper == nil {
		config.Skipper = defaultSPASkipper
	}

	if config.DistPath == "" {
		config.DistPath = "frontend/dist"
	}
	if config.IndexFile == "" {
		config.IndexFile = "index.html"
	}
	if config.DevProxyURL == "" {
		config.DevProxyURL = "http://localhost:5173"
	}

	isDevMode := config.IsDevMode
	if isDevMode {
		// In DEV mode, we CHECK but only WARN if files are missing.
		indexPath := path.Join(config.DistPath, config.IndexFile)
		if _, err := config.DistFS.Open(indexPath); err != nil {
			log.Printf(
				"WARN: SPA assets not found at '%s'. This is okay in dev mode, as requests will be proxied to '%s'. "+
					"However, this will be a FATAL ERROR in production builds",
				indexPath,
				config.DevProxyURL,
			)
		}
	} else {
		// In PROD mode, we CHECK and return a FATAL ERROR if files are missing.
		indexPath := path.Join(config.DistPath, config.IndexFile)
		f, err := config.DistFS.Open(indexPath)
		if err != nil {
			log.Printf(
				"FATAL: SPA assets not found at '%s'. This is a FATAL ERROR in production builds",
				indexPath,
			)
			return nil
		}
		f.Close()
	}
	distDirFS, err := fs.Sub(config.DistFS, config.DistPath)
	if err != nil {
		log.Fatalf("FATAL: failed to create sub-filesystem for dist path '%s': %v", config.DistPath, err)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.Skipper(r) {
				next(w, r)
				return
			}

			if isDevMode {
				handleDevMode(w, r, config.DevProxyURL)
			} else {
				handleProdMode(w, r, distDirFS)
			}
		})
	}
}

func handleDevMode(w http.ResponseWriter, r *http.Request, proxyURL string) {
	target, err := url.Parse(proxyURL)
	if err != nil {
		log.Printf("Failed to parse dev proxy URL: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
}

func handleProdMode(w http.ResponseWriter, r *http.Request, distFS fs.FS) {
	// The path must be relative to the root of the sub-filesystem.
	reqPath := strings.TrimPrefix(r.URL.Path, "/")

	// Try to serve a static file from the filesystem.
	f, err := distFS.Open(reqPath)
	if err == nil { // File exists
		defer f.Close()
		// Use the default file server to handle content types, etc.
		http.FileServer(http.FS(distFS)).ServeHTTP(w, r)
		return
	}

	// If the file does not exist, fall back to serving the index file.
	// This is the key behavior for SPAs.
	r.URL.Path = "/" // Serve the root, which will be index.html
	http.FileServer(http.FS(distFS)).ServeHTTP(w, r)
}
