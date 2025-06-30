#!/bin/bash

# Test build script for WEC CA Docker image
set -e

echo "Testing WEC CA Docker build process..."

# Test Go build first
echo "Step 1: Testing local Go build..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o wec-ca-test .
echo "✓ Local Go build successful"

# Check binary size
BINARY_SIZE=$(du -h wec-ca-test | cut -f1)
echo "✓ Binary size: $BINARY_SIZE"

# Verify it's statically linked
if command -v ldd >/dev/null 2>&1; then
    echo "Checking if binary is statically linked..."
    if ldd wec-ca-test 2>&1 | grep -q "not a dynamic executable"; then
        echo "✓ Binary is statically linked (good for scratch image)"
    else
        echo "⚠ Binary has dynamic dependencies:"
        ldd wec-ca-test
    fi
fi

# Clean up test binary
rm -f wec-ca-test

echo "Step 2: Validating Dockerfile..."

# Check if Dockerfile exists and has correct structure
if [ ! -f "Dockerfile" ]; then
    echo "❌ Dockerfile not found"
    exit 1
fi

# Check for multi-stage build
if grep -q "FROM.*AS builder" Dockerfile && grep -q "FROM scratch" Dockerfile; then
    echo "✓ Multi-stage Dockerfile structure found"
else
    echo "❌ Dockerfile doesn't have proper multi-stage structure"
    exit 1
fi

# Check for security best practices
if grep -q "USER.*65534" Dockerfile; then
    echo "✓ Non-root user configuration found"
else
    echo "⚠ No non-root user found in Dockerfile"
fi

echo "Step 3: Validating Docker Compose files..."

# Check docker-compose.yml
if [ -f "docker-compose.yml" ]; then
    echo "✓ docker-compose.yml found"
else
    echo "❌ docker-compose.yml not found"
    exit 1
fi

# Check production compose file
if [ -f "docker-compose.prod.yml" ]; then
    echo "✓ docker-compose.prod.yml found"
else
    echo "❌ docker-compose.prod.yml not found"
    exit 1
fi

echo "Step 4: Testing configuration..."

# Check if .dockerignore exists
if [ -f ".dockerignore" ]; then
    echo "✓ .dockerignore found"
else
    echo "⚠ .dockerignore not found (build context might be larger)"
fi

# Check if Makefile exists
if [ -f "Makefile" ]; then
    echo "✓ Makefile found"
else
    echo "⚠ Makefile not found"
fi

echo
echo "All validation checks passed! ✓"
echo
echo "To build the Docker image, run:"
echo "  docker build -t wec-ca ."
echo
echo "To start with docker-compose, run:"
echo "  docker-compose up -d"
echo
echo "To test the ACME endpoint, run:"
echo "  curl -k https://localhost:8443/acme/directory"