# Build stage
FROM golang:1.22-bullseye AS build

WORKDIR /agent

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o /agent/agent ./cmd/agent

# Runtime stage
FROM debian:12-slim

# Copy the Go agent binary
COPY --from=build /agent/agent /usr/local/bin/agent

# Copy the precompiled BPF object
COPY bpf/pqexec.bpf.o /pqexec.bpf.o

WORKDIR /

ENV BPF_OBJECT=/pqexec.bpf.o
ENV TARGET_PATTERN=testapp
ENV OUTPUT_FILE=/output/pqexec.log

ENTRYPOINT ["/usr/local/bin/agent"]
