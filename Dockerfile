# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM --platform=$BUILDPLATFORM node:24.22.2-alpine3.24@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS frontend
WORKDIR /src
ARG PREBUILT_FRONTEND=0
COPY package.json package-lock.json ./
RUN if [ "$PREBUILT_FRONTEND" != "1" ]; then npm ci; fi
COPY index.html tsconfig.json tsconfig.node.json vite.config.ts ./
COPY src ./src
COPY public ./public
COPY scripts/build-frontend.mjs ./scripts/build-frontend.mjs
COPY scripts/check-node-runtime.mjs ./scripts/check-node-runtime.mjs
COPY internal/webui/dist ./prebuilt-dist
# Release builds pass the candidate frontend artifact through the Docker
# context. A missing artifact is an error; only local builds run npm.
RUN if [ "$PREBUILT_FRONTEND" = "1" ]; then \
      test -f ./prebuilt-dist/index.html || { echo "prebuilt frontend is missing index.html" >&2; exit 1; }; \
      rm -rf ./internal/webui/dist && mkdir -p ./internal/webui/dist && cp -a ./prebuilt-dist/. ./internal/webui/dist/; \
    else \
      npm run build; \
    fi

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS naabu
ARG NAABU_VERSION=v2.6.1
ARG NAABU_COMMIT=5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8
ARG NAABU_X_NET_VERSION=v0.62.0
ARG NAABU_GOLDMARK_VERSION=v1.8.6
ARG NAABU_COMPRESS_VERSION=v1.20.3
ARG TARGETOS
ARG TARGETARCH
WORKDIR /naabu
COPY scripts/verify-naabu-module-versions.sh /usr/local/bin/verify-naabu-module-versions.sh
RUN apk add --no-cache ca-certificates=20261020-r0 git=2.54.0-r0
# Fetch the immutable commit and the human-readable release tag, then verify
# that the tag still resolves to the pinned commit before compiling.
RUN git init . \
    && git remote add origin https://github.com/projectdiscovery/naabu.git \
    && git fetch --depth 1 origin ${NAABU_COMMIT} \
    && git fetch --depth 1 origin refs/tags/${NAABU_VERSION}:refs/tags/${NAABU_VERSION} \
    && test "$(git rev-parse ${NAABU_VERSION}^{commit})" = "${NAABU_COMMIT}" \
    && git checkout --detach ${NAABU_COMMIT}
# Naabu v2.6.1 pins older x/net, goldmark, and compress versions with known
# advisories. Keep the scanner source pin while resolving those modules at
# fixed releases; Go records the compatible module graph and checksums in this
# build stage. The image scan checks the resulting binary on both architectures.
RUN go get golang.org/x/net@${NAABU_X_NET_VERSION} \
      github.com/yuin/goldmark@${NAABU_GOLDMARK_VERSION} \
      github.com/klauspost/compress@${NAABU_COMPRESS_VERSION} \
    && sh /usr/local/bin/verify-naabu-module-versions.sh \
      "${NAABU_X_NET_VERSION}" "${NAABU_GOLDMARK_VERSION}" "${NAABU_COMPRESS_VERSION}"
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

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates=20261020-r0 git=2.54.0-r0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN rm -rf ./internal/webui/dist
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

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# zlib is part of the base image; pinning it here installs the security
# update that the base image predates.
RUN apk add --no-cache ca-certificates=20261020-r0 gcompat=1.1.0-r4 nmap=7.99-r0 nmap-scripts=7.99-r0 tzdata=2026e-r0 zlib=1.3.2-r1 \
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
