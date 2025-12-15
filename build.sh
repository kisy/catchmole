#!/bin/env bash
set -e

mkdir -p bin

echo "Building for AMD64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/catchmole-amd64 cmd/main.go

echo "Building for ARM64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/catchmole-arm64 cmd/main.go

ls -lh bin/