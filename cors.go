package middleware

import (
	"net/http"

	"github.com/rs/cors"
)

type Options struct {
	AllowedOrigins             []string
	AllowOriginFunc            func(origin string) bool
	AllowOriginRequestFunc     func(r *http.Request, origin string) bool
	AllowOriginVaryRequestFunc func(r *http.Request, origin string) (bool, []string)
	AllowedMethods             []string
	AllowedHeaders             []string
	ExposedHeaders             []string
	MaxAge                     int
	AllowCredentials           bool
	AllowPrivateNetwork        bool
	OptionsPassthrough         bool
	OptionsSuccessStatus       int
	Debug                      bool
	Logger                     Logger
}

type Logger interface {
	Printf(string, ...interface{})
}

// CORSMiddleware returns a middleware with optional configurations
func CORSMiddleware(options Options) Middleware {
	if len(options.AllowedOrigins) == 0 {
		options = Options{
			AllowedOrigins:   []string{"http://localhost:8080", "http://localhost:3001", "http://localhost:3000"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "X-CSRF-Token"},
			ExposedHeaders:   []string{"X-CSRF-Token"},
			AllowCredentials: true,
		}
	}
	handler := cors.New(cors.Options{
		AllowedOrigins:             options.AllowedOrigins,
		AllowOriginFunc:            options.AllowOriginFunc,
		AllowOriginRequestFunc:     options.AllowOriginRequestFunc,
		AllowOriginVaryRequestFunc: options.AllowOriginVaryRequestFunc,
		AllowedMethods:             options.AllowedMethods,
		AllowedHeaders:             options.AllowedHeaders,
		ExposedHeaders:             options.ExposedHeaders,
		MaxAge:                     options.MaxAge,
		AllowCredentials:           options.AllowCredentials,
		AllowPrivateNetwork:        options.AllowPrivateNetwork,
		OptionsPassthrough:         options.OptionsPassthrough,
		OptionsSuccessStatus:       options.OptionsSuccessStatus,
		Debug:                      options.Debug,
		Logger:                     options.Logger,
	})
	return func(next http.HandlerFunc) http.HandlerFunc {
		return handler.Handler(next).ServeHTTP
	}
}
