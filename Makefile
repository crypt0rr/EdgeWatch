VERSION ?= dev
GO_LDFLAGS ?= -s -w -X main.version=$(VERSION)
GOLANGCI_LINT_VERSION ?= $(shell sed -n '1p' .golangci-lint-version)
GOVULNCHECK_VERSION ?= v1.8.0
# CI supplies the pull request base (or the previous push revision). Local
# callers can override this with GOLANGCI_LINT_BASE=...; when it is absent or
# unavailable, fall back to the first parent so a detached checkout remains
# useful.
GOLANGCI_LINT_BASE ?= HEAD^

.PHONY: build frontend test lint-go vulncheck frontend-audit security check

frontend:
	npm ci
	npm run build

build: frontend
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o edgewatch ./cmd/edgewatch

test:
	go test -race -cover ./...

lint-go:
	@base="$(GOLANGCI_LINT_BASE)"; \
	if ! git rev-parse --verify "$${base}^{commit}" >/dev/null 2>&1; then \
		base="$$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse HEAD^)"; \
	fi; \
	GOTOOLCHAIN="$$(go env GOVERSION)" go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --new-from-rev="$${base}" ./...

vulncheck:
	GOTOOLCHAIN="$$(go env GOVERSION)" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

frontend-audit:
	npm audit --audit-level=high

security: lint-go vulncheck frontend-audit

check:
	@test -z "$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...
	npm run lint
	$(MAKE) security
