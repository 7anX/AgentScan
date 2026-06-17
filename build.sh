#!/usr/bin/env bash
# build.sh — AgentScan one-shot build script
# Usage: ./build.sh [os] [arch]
#   ./build.sh              → native binary (current OS/arch)
#   ./build.sh linux amd64  → cross-compile for Linux x86_64
#   ./build.sh windows amd64
#   ./build.sh darwin arm64 → macOS Apple Silicon

set -euo pipefail

NAME="agentscan"
VERSION="0.1.0"
MODULE="github.com/agentscan/agentscan"
OUTPUT_DIR="dist"

GOOS="${1:-$(go env GOOS)}"
GOARCH="${2:-$(go env GOARCH)}"

# 二进制文件名（Windows 加 .exe）
BINARY="${NAME}"
if [[ "${GOOS}" == "windows" ]]; then
    BINARY="${NAME}.exe"
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT="${OUTPUT_DIR}/${BINARY}"

echo "▶ Building ${NAME} v${VERSION} for ${GOOS}/${GOARCH}..."

GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
    -trimpath \
    -ldflags="-s -w -X '${MODULE}/internal/version.Version=${VERSION}' -X '${MODULE}/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" \
    -o "${OUTPUT}" \
    .

echo "✓ Built: ${OUTPUT}"
echo "  Size:  $(du -sh "${OUTPUT}" | cut -f1)"

# 如果是本机平台，快速验证能跑
if [[ "${GOOS}" == "$(go env GOOS)" && "${GOARCH}" == "$(go env GOARCH)" ]]; then
    echo ""
    echo "▶ Verifying binary..."
    "./${OUTPUT}" --version
    echo ""
    echo "▶ Quick help:"
    "./${OUTPUT}" scan --help
fi
