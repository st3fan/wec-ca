# Docker Deployment Guide

This document describes how to build and deploy the WEC CA ACME server using Docker.

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the ACME server
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the server
docker-compose down
```

### Using Docker Build

```bash
# Build the image
docker build -t wec-ca .

# Run the container
docker run -d \
  --name wec-ca \
  -p 8443:8443 \
  -v wec-ca-data:/data \
  -e WECCA_HOSTNAME=your-domain.com \
  -e WECCA_DOMAIN=your-domain.com \
  -e WECCA_SERVER_URL=https://your-domain.com:8443 \
  wec-ca
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WECCA_ADDRESS` | Server bind address | `:8443` |
| `WECCA_HOSTNAME` | Server hostname for certificates | `localhost` |
| `WECCA_DOMAIN` | Domain for which to issue certificates | `localhost` |
| `WECCA_SERVER_URL` | Public URL of the ACME server | `https://localhost:8443` |
| `WECCA_CERT_LIFETIME` | Certificate lifetime | `24h` |

### Volumes

- `/data` - Persistent storage for CA certificates and issued certificates

## Docker Image Details

### Multi-Stage Build

The Dockerfile uses a two-stage build process:

1. **Build Stage** (`golang:1.22-alpine`)
   - Downloads dependencies
   - Compiles the Go application with static linking
   - Strips debug symbols for minimal size

2. **Runtime Stage** (`scratch`)
   - Minimal base image (only ~2MB)
   - Contains only the compiled binary and essential certificates
   - Runs as non-root user (UID 65534)

### Security Features

- **Scratch base image**: Minimal attack surface
- **Non-root user**: Runs as user ID 65534 (nobody)
- **Static linking**: No external dependencies
- **CA certificates included**: For TLS connectivity

### Image Size

The final image is extremely small:
- Base scratch image: ~2MB
- Application binary: ~15-20MB
- CA certificates: ~200KB
- **Total: ~17-22MB**

## Production Deployment

### Prerequisites

1. Valid domain name pointing to your server
2. Firewall allowing traffic on port 8443
3. Docker and Docker Compose installed

### Production Configuration

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  wec-ca:
    build: .
    ports:
      - "8443:8443"
    environment:
      - WECCA_ADDRESS=:8443
      - WECCA_HOSTNAME=acme.yourdomain.com
      - WECCA_DOMAIN=yourdomain.com
      - WECCA_SERVER_URL=https://acme.yourdomain.com:8443
      - WECCA_CERT_LIFETIME=720h  # 30 days
    volumes:
      - ./data:/data
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Health Check

The container includes a health check that verifies the ACME directory endpoint is responding:

```bash
# Check container health
docker-compose ps

# Manual health check
curl -k https://localhost:8443/acme/directory
```

## Troubleshooting

### Build Issues

```bash
# Check build logs
docker build --no-cache -t wec-ca .

# Build with verbose output
docker build --progress=plain -t wec-ca .
```

### Runtime Issues

```bash
# Check container logs
docker-compose logs wec-ca

# Execute shell in container (for debugging)
docker-compose exec wec-ca sh
```

### Common Problems

1. **Port already in use**: Change the host port in docker-compose.yml
2. **Permission denied**: Ensure data volume has correct permissions
3. **Certificate issues**: Check that WECCA_HOSTNAME matches your domain

## Development

### Development with Docker

```bash
# Development build with hot reload (if needed)
docker build --target builder -t wec-ca-dev .

# Run development container
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  golang:1.22-alpine \
  go run .
```

### Testing the Build

```bash
# Test the production build locally
docker build -t wec-ca-test .
docker run --rm -p 8443:8443 wec-ca-test

# Test with curl
curl -k https://localhost:8443/acme/directory
```