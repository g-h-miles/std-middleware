# std-middleware

A Go middleware package for standard HTTP request/response handling.

## Project Structure

```
std-middleware/
├── cmd/
│   └── server/          # Test HTTP server
│       └── main.go
├── .air.toml           # Air hot reload configuration
├── Makefile            # Build and development tasks
├── go.mod              # Go module file
└── README.md
```

## Quick Start

### Prerequisites

- Go 1.21 or later
- Air (for hot reloading): `go install github.com/cosmtrek/air@latest`

### Development

1. **Run in development mode with hot reload:**

   ```bash
   make dev
   ```

2. **Run the test server:**

   ```bash
   make run
   ```

3. **Build the application:**
   ```bash
   make build
   ```

### Testing the Server

Once the server is running, you can test the endpoints:

- **Root endpoint:** `curl http://localhost:8080/`
- **Hello endpoint:** `curl http://localhost:8080/hello`
- **Health endpoint:** `curl http://localhost:8080/health`

### Available Make Commands

- `make build` - Build the application
- `make run` - Run the test server
- `make dev` - Run with hot reload (requires Air)
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make deps` - Install and tidy dependencies
- `make fmt` - Format code
- `make vet` - Vet code

## Middleware Examples

The test server includes example middleware:

- **LoggingMiddleware** - Logs request details and timing
- **CORSMiddleware** - Adds CORS headers for cross-origin requests

## Development

This project is set up for easy development with:

- Hot reloading via Air
- Comprehensive Makefile for common tasks
- Standard library only (no external dependencies for core functionality)
- Clean project structure suitable for middleware development
