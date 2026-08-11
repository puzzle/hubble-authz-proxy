# syntax=docker/dockerfile:1

FROM golang:1.26 AS build

ARG OCI_VERSION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Warm the module cache separately so source edits do not refetch dependencies.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# CGO_ENABLED=0 keeps the binary static so it runs on the distroless base.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${OCI_VERSION}" \
    -o /out/hubble-authz-proxy .

FROM gcr.io/distroless/static-debian12:nonroot

ARG OCI_VERSION=dev
ARG OCI_REVISION=unknown
ARG OCI_CREATED=unknown

LABEL org.opencontainers.image.title="hubble-authz-proxy" \
      org.opencontainers.image.description="Namespace-scoped authorization proxy for the Hubble UI" \
      org.opencontainers.image.source="https://github.com/splattner/hubble-authz-proxy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.created="${OCI_CREATED}"

COPY --from=build /out/hubble-authz-proxy /usr/local/bin/hubble-authz-proxy

USER nonroot:nonroot
EXPOSE 8090

ENTRYPOINT ["/usr/local/bin/hubble-authz-proxy"]
