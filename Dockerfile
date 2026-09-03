# syntax=docker/dockerfile:1.27
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/edgewatch ./cmd/edgewatch

FROM alpine:3.22
RUN apk add --no-cache ca-certificates nmap tzdata \
    && mkdir -p /etc/edgewatch /var/lib/edgewatch /run/secrets \
    && chmod 0750 /etc/edgewatch /var/lib/edgewatch /run/secrets
COPY --from=build /out/edgewatch /usr/local/bin/edgewatch
ENTRYPOINT ["edgewatch"]
CMD ["daemon", "--config", "/etc/edgewatch/config.yaml"]
