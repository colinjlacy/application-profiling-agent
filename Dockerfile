# Build stage
FROM golang:1.25.1-bullseye AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# You need to precompile the BPF program separately and include integration_bpf.o
# e.g. via a separate Docker stage or local build.
RUN go build -o /out/agent ./cmd/agent

# Runtime stage
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/agent /usr/local/bin/agent
COPY bpf/integration_bpf.o /usr/lib/integration_bpf.o

WORKDIR /
ENV OUT_DIR=/out
ENTRYPOINT ["/usr/local/bin/agent"]
