.PHONY: build frontend test check

frontend:
	npm ci
	npm run build

build: frontend
	go build -trimpath -o edgewatch ./cmd/edgewatch

test:
	go test -race -cover ./...

check:
	gofmt -w cmd internal
	go vet ./...
	go test -race ./...
	npm run lint
