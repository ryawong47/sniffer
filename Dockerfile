# Multi-stage build for smaller final image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libpcap-dev \
    linux-headers

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the test application
RUN go build -o sniffer-test test_sniffer.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    ca-certificates

# Copy the binary from builder
COPY --from=builder /app/sniffer-test /usr/local/bin/sniffer-test

# Create a non-root user
RUN adduser -D -u 1000 sniffer

# The binary needs CAP_NET_RAW capability to capture packets
RUN setcap cap_net_raw=+ep /usr/local/bin/sniffer-test

# Switch to non-root user
USER sniffer

# Run the application
ENTRYPOINT ["sniffer-test"]