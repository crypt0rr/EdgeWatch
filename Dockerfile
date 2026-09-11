# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
FROM --platform=$BUILDPLATFORM node:24.16.0-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a AS frontend
WORKDIR /src
ARG PREBUILT_FRONTEND=0
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig.json tsconfig.node.json vite.config.ts ./
COPY src ./src
COPY scripts/build-frontend.mjs ./scripts/build-frontend.mjs
COPY internal/webui/dist ./prebuilt-dist
# Release builds pass the candidate frontend artifact through the Docker
# context. Local builds retain the self-contained Node build fallback.
RUN if [ "$PREBUILT_FRONTEND" = "1" ] && [ -f ./prebuilt-dist/index.html ]; then \
      rm -rf ./internal/webui/dist && mkdir -p ./internal/webui/dist && cp -a ./prebuilt-dist/. ./internal/webui/dist/; \
    else \
      npm run build; \
    fi

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS naabu
ARG NAABU_VERSION=v2.6.1
ARG NAABU_COMMIT=5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8
ARG TARGETOS
ARG TARGETARCH
WORKDIR /naabu
RUN apk add --no-cache ca-certificates=20260611-r0 git=2.54.0-r0
# Fetch the immutable commit and the human-readable release tag, then verify
# that the tag still resolves to the pinned commit before compiling.
RUN git init . \
    && git remote add origin https://github.com/projectdiscovery/naabu.git \
    && git fetch --depth 1 origin ${NAABU_COMMIT} \
    && git fetch --depth 1 origin refs/tags/${NAABU_VERSION}:refs/tags/${NAABU_VERSION} \
    && test "$(git rev-parse ${NAABU_VERSION}^{commit})" = "${NAABU_COMMIT}" \
    && git checkout --detach ${NAABU_COMMIT}
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/naabu ./cmd/naabu

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates=20260611-r0 git=2.54.0-r0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/webui/dist ./internal/webui/dist
ARG VERSION=dev
ARG PREBUILT_EDGEWATCH=0
ARG TARGETOS
ARG TARGETARCH
RUN if [ "$PREBUILT_EDGEWATCH" = "1" ]; then \
      test -f "/src/release-binaries/linux_${TARGETARCH}/edgewatch" && \
      mkdir -p /out && \
      install -m 0755 "/src/release-binaries/linux_${TARGETARCH}/edgewatch" /out/edgewatch; \
    else \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/edgewatch ./cmd/edgewatch; \
    fi

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates=20260611-r0 nmap=7.99-r0 nmap-scripts=7.99-r0 tzdata=2026c-r0 \
    && mkdir -p /etc/edgewatch /var/lib/edgewatch /run/secrets \
    && chmod 0750 /etc/edgewatch /var/lib/edgewatch /run/secrets
COPY --from=build /out/edgewatch /usr/local/bin/edgewatch
COPY --from=naabu /out/naabu /usr/local/bin/naabu
ENTRYPOINT ["edgewatch"]
CMD ["daemon", "--config", "/etc/edgewatch/config.yaml"]
