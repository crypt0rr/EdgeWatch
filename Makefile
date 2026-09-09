VERSION ?= dev
GO_LDFLAGS ?= -s -w -X main.version=$(VERSION)

.PHONY: build frontend test check

frontend:
	npm ci
	npm run build

build: frontend
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o edgewatch ./cmd/edgewatch

test:
	go test -race -cover ./...

check:
	gofmt -w cmd internal
	go vet ./...
	go test -race ./...
	npm run lint
