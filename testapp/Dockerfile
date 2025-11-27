FROM golang:1.22-bullseye

# We need libpq headers + libs for CGO + runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# This will be the place we build AND run from.
WORKDIR /app

# Copy module files first to leverage Docker cache.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source.
COPY . .

# Build the binary. For Apple Silicon / aarch64 Linux, GOARCH=arm64 is fine.
# If you're on Intel and using linux/amd64 images, you can drop GOARCH=arm64.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o testapp main.go

# Default working directory when the container starts.
WORKDIR /app

# Run the app binary.
CMD ["./testapp"]
