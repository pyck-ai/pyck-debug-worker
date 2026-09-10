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

FROM ghcr.io/pyck-ai/baseimages/static:latest

COPY --from=build /out/pyck-debug-worker /pyck-debug-worker

ENTRYPOINT ["/pyck-debug-worker"]
