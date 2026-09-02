#!/usr/bin/env bash
# ==============================================================================
# BountyScope V2 — Kali Linux Security Tools Installer
# Idempotent installation script for Kali Linux / Debian environments
# ==============================================================================

set -e

echo "=================================================================="
echo "🛡️  BountyScope V2 — Kali Linux Tooling Setup"
echo "=================================================================="

# 1. System packages
echo "[+] Updating apt repositories and installing core dependencies..."
sudo apt update -y
sudo apt install -y git curl build-essential pkg-config libssl-dev libsqlite3-dev

# 2. Verify or Install Go
if ! command -v go &> /dev/null; then
    echo "[+] Go not found in PATH. Installing golang-go..."
    sudo apt install -y golang-go
fi

echo "[+] Go version: $(go version)"

# Setup GOPATH and PATH
export GOPATH="${HOME}/go"
export PATH="${PATH}:${GOPATH}/bin:/usr/local/bin"
mkdir -p "${GOPATH}/bin"

# 3. Install/Update Security Tools
echo "[+] Installing ProjectDiscovery & Recon tooling via Go..."

# subfinder
if ! command -v subfinder &> /dev/null && [ ! -f "${GOPATH}/bin/subfinder" ]; then
    echo "  -> Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
    echo "  -> [OK] subfinder already installed."
fi

# httpx
if ! command -v httpx &> /dev/null && [ ! -f "${GOPATH}/bin/httpx" ]; then
    echo "  -> Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    echo "  -> [OK] httpx already installed."
fi

# katana
if ! command -v katana &> /dev/null && [ ! -f "${GOPATH}/bin/katana" ]; then
    echo "  -> Installing katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
else
    echo "  -> [OK] katana already installed."
fi

# gau
if ! command -v gau &> /dev/null && [ ! -f "${GOPATH}/bin/gau" ]; then
    echo "  -> Installing gau..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest
else
    echo "  -> [OK] gau already installed."
fi

# nuclei
if ! command -v nuclei &> /dev/null && [ ! -f "${GOPATH}/bin/nuclei" ]; then
    echo "  -> Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
else
    echo "  -> [OK] nuclei already installed."
fi

# Optional: Symlink to /usr/local/bin if writable or user desires
echo "[+] Creating symlinks in /usr/local/bin if needed..."
for tool in subfinder httpx katana gau nuclei; do
    if [ -f "${GOPATH}/bin/${tool}" ] && [ ! -f "/usr/local/bin/${tool}" ]; then
        sudo ln -sf "${GOPATH}/bin/${tool}" "/usr/local/bin/${tool}" || true
    fi
done

echo ""
echo "=================================================================="
echo "🔍 Verifying Installed Binaries:"
echo "=================================================================="
command -v subfinder && subfinder -version || echo "[!] subfinder path check failed"
command -v httpx && httpx -version || echo "[!] httpx path check failed"
command -v katana && katana -version || echo "[!] katana path check failed"
command -v gau && gau --version || echo "[!] gau path check failed"
command -v nuclei && nuclei -version || echo "[!] nuclei path check failed"

echo ""
echo "✅ Tool installation completed successfully."
echo "   Make sure '${HOME}/go/bin' is added to your PATH in ~/.zshrc or ~/.bashrc:"
echo "   export PATH=\$PATH:\$HOME/go/bin"
