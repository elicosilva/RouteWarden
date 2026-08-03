# Build stage: needs a C toolchain because tree-sitter grammars are CGO.
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -o /out/routewarden ./cmd/server

# Runtime stage: enxuto, sem toolchain de build (rule R9: custo de infra
# baixo, roda numa VPS pequena).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/routewarden ./routewarden
COPY rules.yaml ./rules.yaml

EXPOSE 8080

ENTRYPOINT ["./routewarden"]
