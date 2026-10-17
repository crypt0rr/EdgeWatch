# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM --platform=$BUILDPLATFORM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS frontend
WORKDIR /src
ARG PREBUILT_FRONTEND=0
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig.json tsconfig.node.json vite.config.ts ./
COPY src ./src
COPY scripts/build-frontend.mjs ./scripts/build-frontend.mjs
COPY scripts/check-node-runtime.mjs ./scripts/check-node-runtime.mjs
COPY internal/webui/dist ./prebuilt-dist
# Release builds pass the candidate frontend artifact through the Docker
# context. Local builds retain the self-contained Node build fallback.
RUN if [ "$PREBUILT_FRONTEND" = "1" ] && [ -f ./prebuilt-dist/index.html ]; then \
      rm -rf ./internal/webui/dist && mkdir -p ./internal/webui/dist && cp -a ./prebuilt-dist/. ./internal/webui/dist/; \
    else \
      npm run build; \
    fi

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS naabu
ARG NAABU_VERSION=v2.6.1
ARG NAABU_COMMIT=5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8
ARG TARGETOS
ARG TARGETARCH
WORKDIR /naabu
RUN apk add --no-cache ca-certificates=20260909-r0 git=2.54.0-r0
# Fetch the immutable commit and the human-readable release tag, then verify
# that the tag still resolves to the pinned commit before compiling.
RUN git init . \
    && git remote add origin https://github.com/projectdiscovery/naabu.git \
    && git fetch --depth 1 origin ${NAABU_COMMIT} \
    && git fetch --depth 1 origin refs/tags/${NAABU_VERSION}:refs/tags/${NAABU_VERSION} \
    && test "$(git rev-parse ${NAABU_VERSION}^{commit})" = "${NAABU_COMMIT}" \
    && git checkout --detach ${NAABU_COMMIT}
# Naabu's dependencies import symbols dynamically even without cgo, so the
# binary needs an ELF interpreter. Go names the build host's loader, which for
# a cross-compiled architecture is glibc's; gcompat would then re-execute it
# through ld-musl under another process name. Name the target's musl loader,
# as a native build does, and refuse any other.
RUN case "${TARGETARCH}" in \
      amd64) loader=/lib/ld-musl-x86_64.so.1 ;; \
      arm64) loader=/lib/ld-musl-aarch64.so.1 ;; \
      *) echo "no musl loader known for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -I ${loader}" -o /out/naabu ./cmd/naabu \
    && printf '%s\n' 'package main' 'import ("debug/elf"; "fmt"; "os")' \
      'func main() { f, err := elf.Open(os.Args[1]); if err != nil { panic(err) }; for _, p := range f.Progs { if p.Type == elf.PT_INTERP { b := make([]byte, p.Filesz); if _, err := p.ReadAt(b, 0); err != nil { panic(err) }; fmt.Print(string(b[:len(b)-1])) } } }' \
      >/tmp/interp.go \
    && interp="$(go run /tmp/interp.go /out/naabu)" \
    && if [ -n "${interp}" ] && [ "${interp}" != "${loader}" ]; then echo "naabu names ${interp}, not ${loader}" >&2; exit 1; fi

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates=20260909-r0 git=2.54.0-r0
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

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# zlib is part of the base image; pinning it here installs the security
# update that the base image predates.
RUN apk add --no-cache ca-certificates=20260909-r0 gcompat=1.1.0-r4 nmap=7.99-r0 nmap-scripts=7.99-r0 tzdata=2026e-r0 zlib=1.3.2-r1 \
    && mkdir -p /etc/edgewatch /var/lib/edgewatch /run/secrets \
    && chmod 0750 /etc/edgewatch /var/lib/edgewatch /run/secrets \
    && addgroup -S -g 65532 edgewatch-scanner \
    && adduser -S -D -H -u 65532 -G edgewatch-scanner -h /nonexistent -s /sbin/nologin edgewatch-scanner \
    && addgroup -S -g 65531 edgewatch-notify \
    && adduser -S -D -H -u 65531 -G edgewatch-notify -h /nonexistent -s /sbin/nologin edgewatch-notify
COPY --from=build /out/edgewatch /usr/local/bin/edgewatch
COPY --from=naabu /out/naabu /usr/local/bin/naabu
COPY LICENSE LICENSE.md THIRD_PARTY_LICENSES.md /usr/share/licenses/edgewatch/
COPY --from=naabu /naabu/LICENSE.md /usr/share/licenses/naabu/LICENSE.md
ENTRYPOINT ["edgewatch"]
CMD ["daemon", "--config", "/etc/edgewatch/config.yaml"]
