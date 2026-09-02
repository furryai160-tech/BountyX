# ────────────────────────────────────────────────────────────────
# BountyScope - Multi-Stage Dockerfile  (19 Tools + Rust Engine)
# Deploy on Railway, Fly.io, or any Docker host
# ────────────────────────────────────────────────────────────────

# ── Stage 1: Build all Go security tools ────────────────────────
FROM golang:latest AS go-tools
RUN apt-get update && apt-get install -y git ca-certificates --no-install-recommends && rm -rf /var/lib/apt/lists/*
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
RUN go install -v github.com/projectdiscovery/interactsh/pkg/server@latest || true

# XSS / Injection tools
RUN go install -v github.com/hahwul/dalfox/v2@latest
RUN go install -v github.com/Emoe/kxss@latest || go install -v github.com/tomnomnom/kxss@latest || true

# Recon tools
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/zricethezav/gitleaks/v8@latest
RUN go install -v github.com/jaeles-project/gospider@latest
RUN go install -v github.com/tomnomnom/gf@latest
RUN go install -v github.com/owasp-amass/amass/v4/...@latest || true

# CRLF
RUN go install -v github.com/dwisiswant0/crlfuzz@latest || true

# kxss
RUN go install -v github.com/tomnomnom/hacks/kxss@latest || \
    (mkdir -p /go/bin && printf '#!/bin/sh\ncat\n' > /go/bin/kxss && chmod +x /go/bin/kxss)

# Ensure optional binaries exist (create stubs if install failed)
RUN for tool in kxss crlfuzz amass; do \
      if [ ! -f /go/bin/$tool ]; then \
        printf '#!/bin/sh\necho "[STUB] %s: not available in this build"\nexit 1\n' "$tool" > /go/bin/$tool && chmod +x /go/bin/$tool; \
      fi; \
    done

# ── Stage 2: Build Rust binary ────────────────────────────────────
FROM rust:1.88-slim-bookworm AS rust-builder
RUN apt-get update && apt-get install -y \
    libsqlite3-dev pkg-config build-essential ca-certificates \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/bountyscope

# Cache dependencies layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build real source
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release

# ── Stage 3: Python tools ─────────────────────────────────────────
FROM python:3.11-slim-bookworm AS python-tools
RUN apt-get update && apt-get install -y git --no-install-recommends && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir arjun sqlmap paramspider

# Clone smuggler (no PyPI)
RUN git clone --depth=1 https://github.com/defparam/smuggler.git /opt/smuggler

# ── Stage 4: Final Runtime Image ──────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates tzdata libsqlite3-0 curl bash \
    python3 python3-pip git \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all Go tools
COPY --from=go-tools /go/bin/subfinder   /usr/local/bin/subfinder
COPY --from=go-tools /go/bin/httpx       /usr/local/bin/httpx
COPY --from=go-tools /go/bin/katana      /usr/local/bin/katana
COPY --from=go-tools /go/bin/gau         /usr/local/bin/gau
COPY --from=go-tools /go/bin/nuclei      /usr/local/bin/nuclei
COPY --from=go-tools /go/bin/naabu       /usr/local/bin/naabu
COPY --from=go-tools /go/bin/dnsx        /usr/local/bin/dnsx
COPY --from=go-tools /go/bin/alterx      /usr/local/bin/alterx
COPY --from=go-tools /go/bin/dalfox      /usr/local/bin/dalfox
COPY --from=go-tools /go/bin/ffuf        /usr/local/bin/ffuf
COPY --from=go-tools /go/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=go-tools /go/bin/gospider    /usr/local/bin/gospider
COPY --from=go-tools /go/bin/gf          /usr/local/bin/gf
# Optional tools (built above, may not exist if build failed - handled with || true in RUN)
RUN mkdir -p /tmp/optional-bins
COPY --from=go-tools /go/bin/kxss        /usr/local/bin/kxss
COPY --from=go-tools /go/bin/crlfuzz     /usr/local/bin/crlfuzz
COPY --from=go-tools /go/bin/amass       /usr/local/bin/amass

# Copy Python tools
COPY --from=python-tools /usr/local/bin/arjun        /usr/local/bin/arjun
COPY --from=python-tools /usr/local/bin/sqlmap       /usr/local/bin/sqlmap
COPY --from=python-tools /usr/local/lib/python3.11   /usr/local/lib/python3.11
COPY --from=python-tools /opt/smuggler               /opt/smuggler

# Wrapper for smuggler
RUN echo '#!/bin/bash\npython3 /opt/smuggler/smuggler.py "$@"' > /usr/local/bin/smuggler && chmod +x /usr/local/bin/smuggler

# Wrapper for paramspider
RUN echo '#!/bin/bash\npython3 -m paramspider "$@"' > /usr/local/bin/paramspider && chmod +x /usr/local/bin/paramspider

# Copy Rust engine
COPY --from=rust-builder /usr/src/bountyscope/target/release/bountyscope /usr/local/bin/bountyscope
COPY migrations ./migrations

# Create directories
RUN mkdir -p /app/data /app/reports /app/logs /root/.config/subfinder /root/.config/nuclei

# Download nuclei templates (optional, can be done at runtime)
# RUN nuclei -update-templates 2>/dev/null || true

# Environment defaults (override via Railway ENV vars)
ENV DATABASE_URL="sqlite:///app/data/bountyscope.db" \
    DATA_DIR="/app/data" \
    REPORTS_DIR="/app/reports" \
    LOGS_DIR="/app/logs" \
    SUBFINDER_PATH="subfinder" \
    HTTPX_PATH="httpx" \
    KATANA_PATH="katana" \
    GAU_PATH="gau" \
    NUCLEI_PATH="nuclei" \
    DALFOX_PATH="dalfox" \
    NAABU_PATH="naabu" \
    DNSX_PATH="dnsx" \
    FFUF_PATH="ffuf" \
    ALTERX_PATH="alterx" \
    GOSPIDER_PATH="gospider" \
    GITLEAKS_PATH="gitleaks" \
    ARJUN_PATH="arjun" \
    SQLMAP_PATH="sqlmap" \
    SMUGGLER_PATH="smuggler" \
    PARAMSPIDER_PATH="paramspider" \
    AMASS_PATH="amass" \
    CRLFUZZ_PATH="crlfuzz" \
    KXSS_PATH="kxss" \
    MAX_CONCURRENT_JOBS=5 \
    REQUEST_TIMEOUT_SECONDS=30 \
    PROCESS_TIMEOUT_SECONDS=600 \
    NUCLEI_SEVERITIES="medium,high,critical" \
    SCOPE_POLL_INTERVAL_SECONDS=300

EXPOSE 8080

CMD ["/usr/local/bin/bountyscope", "monitor"]



