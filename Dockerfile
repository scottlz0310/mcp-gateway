# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/mcp-gateway ./cmd/server
# Pre-create /out/data; COPY --chown in the final stage sets nonroot ownership
# so Docker copies it into a new named volume on first mount, giving nonroot
# write access without an init container.
RUN mkdir -p /out/data

# distroless: no shell, no package manager
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/mcp-gateway /mcp-gateway
COPY --chown=nonroot:nonroot --from=builder /out/data /data
EXPOSE 8080
# Trivy DS-0002: explicitly declare non-root user (distroless:nonroot UID=65532)
USER nonroot:nonroot
ENTRYPOINT ["/mcp-gateway"]
