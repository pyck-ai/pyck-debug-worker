# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM ghcr.io/pyck-ai/baseimages/golang:${GO_VERSION}-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -trimpath \
      -tags netgo,osusergo \
      -ldflags="-s -w -X github.com/pyck-ai/pyck-debug-worker/internal/buildinfo.version=$VERSION -X github.com/pyck-ai/pyck-debug-worker/internal/buildinfo.commit=$COMMIT" \
      -o /out/pyck-debug-worker \
      ./cmd/pyck-debug-worker

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY <<EOF /etc/nsswitch.conf
hosts: files dns
EOF
COPY --from=build /out/pyck-debug-worker /pyck-debug-worker

USER 65532:65532
ENTRYPOINT ["/pyck-debug-worker"]
