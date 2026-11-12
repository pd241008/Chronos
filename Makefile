#!/usr/bin/env bash
# Chronos top-level build

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[chronos] Building kernel eBPF..."
make -C "$ROOT/kernel/ebpf"

echo "[chronos] Building Go daemon..."
(cd "$ROOT/go" && go build -o chronosd .)

echo "[chronos] Build complete."
