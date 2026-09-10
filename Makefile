VERSION ?= dev
GO_LDFLAGS ?= -s -w -X main.version=$(VERSION)
GOLANGCI_LINT_VERSION ?= $(shell sed -n '1p' .golangci-lint-version)
GOVULNCHECK_VERSION ?= v1.8.0

.PHONY: build frontend test lint-go vulncheck frontend-audit security check

frontend:
	npm ci
	npm run build

build: frontend
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o edgewatch ./cmd/edgewatch

test:
	go test -race -cover ./...

lint-go:
	GOTOOLCHAIN="$$(go env GOVERSION)" go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --new-from-rev=HEAD^ ./...

vulncheck:
	GOTOOLCHAIN="$$(go env GOVERSION)" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

frontend-audit:
	npm audit --audit-level=high

security: lint-go vulncheck frontend-audit

check:
	gofmt -w cmd internal
	go vet ./...
	go test -race ./...
	npm run lint
	$(MAKE) security
