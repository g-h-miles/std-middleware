package middleware

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"testing"
)

//go:embed testdata
var testFS embed.FS

func TestSPA(t *testing.T) {
	// Create a mock dev server
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("dev server response"))
	}))
	defer devServer.Close()

	tests := []struct {
		name           string
		config         SPAConfig
		path           string
		expectError    bool
		shouldCallNext bool
	}{
		{
			name: "valid production config",
			config: SPAConfig{
				DistFS:    testFS,
				DistPath:  "testdata",
				IndexFile: "index.html",
			},
			path:           "/",
			expectError:    false,
			shouldCallNext: false,
		},
		{
			name: "valid dev config",
			config: SPAConfig{
				DistFS:      testFS,
				DistPath:    "testdata",
				IndexFile:   "index.html",
				IsDevMode:   true,
				DevProxyURL: devServer.URL,
			},
			path:           "/",
			expectError:    false,
			shouldCallNext: false,
		},
		{
			name: "invalid dist path",
			config: SPAConfig{
				DistFS:    testFS,
				DistPath:  "nonexistent",
				IndexFile: "index.html",
			},
			path:           "/",
			expectError:    true,
			shouldCallNext: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			middleware := SPA(tc.config)
			if tc.expectError {
				if middleware != nil {
					t.Error("expected nil middleware but got one")
				}
				return
			}
			if middleware == nil {
				t.Fatal("unexpected nil middleware")
			}

			// Create a test handler that will be called if the middleware passes through
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Create the full handler chain
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status %d but got %d", http.StatusOK, rec.Code)
			}
			if nextCalled != tc.shouldCallNext {
				t.Errorf("expected next handler called to be %v but got %v", tc.shouldCallNext, nextCalled)
			}
		})
	}
}

func TestSPASkipper(t *testing.T) {
	config := SPAConfig{
		DistFS:    testFS,
		DistPath:  "testdata",
		IndexFile: "index.html",
	}

	middleware := SPA(config)
	if middleware == nil {
		t.Fatal("unexpected nil middleware")
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name:           "api path should be skipped",
			path:           "/api/users",
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name:           "non-api path should be handled",
			path:           "/dashboard",
			expectedStatus: http.StatusOK,
			shouldCallNext: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Create the full handler chain
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d but got %d", tc.expectedStatus, rec.Code)
			}
			if nextCalled != tc.shouldCallNext {
				t.Errorf("expected next handler called to be %v but got %v", tc.shouldCallNext, nextCalled)
			}
		})
	}
}

func TestSPAStaticFileServing(t *testing.T) {
	config := SPAConfig{
		DistFS:    testFS,
		DistPath:  "testdata",
		IndexFile: "index.html",
	}

	middleware := SPA(config)
	if middleware == nil {
		t.Fatal("unexpected nil middleware")
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		shouldCallNext bool
	}{
		{
			name:           "existing static file",
			path:           "/static/test.txt",
			expectedStatus: http.StatusOK,
			shouldCallNext: false,
		},
		{
			name:           "non-existent file should serve index",
			path:           "/nonexistent",
			expectedStatus: http.StatusOK,
			shouldCallNext: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Create the full handler chain
			handler := middleware(next)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d but got %d", tc.expectedStatus, rec.Code)
			}
			if nextCalled != tc.shouldCallNext {
				t.Errorf("expected next handler called to be %v but got %v", tc.shouldCallNext, nextCalled)
			}
		})
	}
}
