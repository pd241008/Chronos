#!/usr/bin/env bash
# Chronos environment setup (Linux 6.2 / Ubuntu 22.04, bare-metal or VM)
# Installs eBPF toolchain, Go, Lean 4, and benchmark dependencies.

set -euo pipefail

echo "[chronos] Installing eBPF toolchain..."
apt-get update -y
apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic \
  linux-headers-$(uname -r) bpftool gcc make git curl

echo "[chronos] Installing Go..."
if ! command -v go &>/dev/null; then
  curl -L https://go.dev/dl/go1.22.linux-amd64.tar.gz -o /tmp/go.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
fi

echo "[chronos] Installing Lean 4..."
if ! command -v lean &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://leanprover.github.io/lean.sh | sh
fi

echo "[chronos] Setup complete. Verify: clang --version, go version, lean --version"
