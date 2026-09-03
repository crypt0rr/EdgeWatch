.PHONY: build test check

build:
	go build -trimpath -o edgewatch ./cmd/edgewatch

test:
	go test -race -cover ./...

check:
	gofmt -w cmd internal
	go vet ./...
	go test -race ./...
