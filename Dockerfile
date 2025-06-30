# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
# CGO_ENABLED=0 ensures static linking for scratch compatibility
# -ldflags="-s -w" strips debug info to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o wec-ca \
    .

# Runtime stage
FROM scratch

# Copy CA certificates from builder for TLS connectivity
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data for proper time handling
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder stage
COPY --from=builder /app/wec-ca /wec-ca

# Create data directory structure
# Note: scratch doesn't have mkdir, so we'll handle this in the app
VOLUME ["/data"]

# Expose HTTPS port (ACME servers typically use HTTPS)
EXPOSE 8443

# Set environment variables
ENV WECCA_ADDRESS=:8443
ENV WECCA_HOSTNAME=localhost
ENV WECCA_DOMAIN=localhost
ENV WECCA_SERVER_URL=https://localhost:8443
ENV TZ=UTC

# Run as non-root user (user ID 65534 is 'nobody' in most systems)
USER 65534:65534

# Start the application
ENTRYPOINT ["/wec-ca"]