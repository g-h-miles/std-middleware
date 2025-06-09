.PHONY: test clean deps fmt vet

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/


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
