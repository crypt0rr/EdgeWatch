VERSION ?= dev
GO_LDFLAGS ?= -s -w -X main.version=$(VERSION)
GOLANGCI_LINT_VERSION ?= $(shell sed -n '1p' .golangci-lint-version)
GOVULNCHECK_VERSION ?= v1.9.0
export GOLANGCI_LINT_BASE
# CI supplies the pull request base (or the previous push revision). Local
# callers can override this with GOLANGCI_LINT_BASE=...; the resolver treats
# an empty, unavailable, or HEAD-equal base as missing so lint never silently
# succeeds against an empty diff.

.PHONY: build frontend test lint-go vulncheck frontend-audit security check

frontend:
	npm ci
	npm run build

build: frontend
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o edgewatch ./cmd/edgewatch

test:
	go test -race -timeout=25m -cover ./...

lint-go:
	@base="$$(./scripts/resolve-lint-base.sh)" || exit $$?; \
	GOTOOLCHAIN="$$(go env GOVERSION)" go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --new-from-rev="$${base}" ./...

vulncheck:
	GOTOOLCHAIN="$$(go env GOVERSION)" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

frontend-audit:
	npm audit --audit-level=high

security: lint-go vulncheck frontend-audit

check:
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))"
	go vet ./...
	go test -race -timeout=25m ./...
	npm run lint
	$(MAKE) security
