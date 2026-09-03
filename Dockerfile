# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
FROM --platform=$BUILDPLATFORM node:24.8.0-alpine3.22@sha256:3e843c608bb5232f39ecb2b25e41214b958b0795914707374c8acc28487dea17 AS frontend
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig.json tsconfig.node.json vite.config.ts ./
COPY src ./src
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates=20260611-r0 git=2.54.0-r0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/webui/dist ./internal/webui/dist
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/edgewatch ./cmd/edgewatch

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates=20260611-r0 nmap=7.99-r0 tzdata=2026c-r0 \
    && mkdir -p /etc/edgewatch /var/lib/edgewatch /run/secrets \
    && chmod 0750 /etc/edgewatch /var/lib/edgewatch /run/secrets
COPY --from=build /out/edgewatch /usr/local/bin/edgewatch
ENTRYPOINT ["edgewatch"]
CMD ["daemon", "--config", "/etc/edgewatch/config.yaml"]
