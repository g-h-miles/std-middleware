.PHONY: build run test clean dev

# Build the application
build:
	go build -o bin/server ./cmd/server

# Run the test server
run:
	go run ./cmd/server

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Development mode with air hot reload
dev:
	air

# Install dependencies
deps:
	go mod tidy
	go mod download

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...
