#!/bin/env bash
set -e

mkdir -p bin
mkdir -p web/static

# Download static assets if they don't exist
if [ ! -f web/static/pico.min.css ]; then
    echo "Downloading pico.min.css..."
    curl -L -o web/static/pico.min.css "https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"
fi

if [ ! -f web/static/alpine.js ]; then
    echo "Downloading alpine.js..."
    curl -L -o web/static/alpine.js "https://unpkg.com/alpinejs"
fi

echo "Building for AMD64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/catchmole-amd64 cmd/main.go

echo "Building for ARM64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/catchmole-arm64 cmd/main.go

ls -lh bin/