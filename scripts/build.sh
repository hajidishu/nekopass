#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 scripts/check-public.py
go test ./...
(cd web && npm ci && npm run build)
mkdir -p dist/bin
tr -d '\r' < scripts/nekopassctl.sh > dist/bin/nekopassctl
chmod 755 dist/bin/nekopassctl
CGO_ENABLED=0 go build -trimpath -o dist/bin/nekopass ./cmd/nekopass
CGO_ENABLED=0 go build -trimpath -o dist/bin/nekopass-agent ./cmd/nekopass-agent
