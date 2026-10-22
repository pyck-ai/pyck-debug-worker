# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM ghcr.io/pyck-ai/baseimages/golang:${GO_VERSION}-alpine AS build

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

# Working directory for --netcheck (writes netcheck/ here), owned by the
# runtime user so a named volume mounted on it is writable.
RUN mkdir -p /out/data

FROM ghcr.io/pyck-ai/baseimages/static:latest

COPY --from=build /out/pyck-debug-worker /pyck-debug-worker
COPY --from=build --chown=1001:1001 /out/data /data

WORKDIR /data

ENTRYPOINT ["/pyck-debug-worker"]
