#!/usr/bin/env bash
set -euo pipefail

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared not found. Install first: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
  exit 1
fi

if [ -n "${1:-}" ]; then
  # Named tunnel mode (requires Cloudflare tunnel config), e.g. ./start-tunnel.sh ai-chatbot-backend
  exec cloudflared tunnel run "$1"
fi

# Quick tunnel mode (*.cfargotunnel.com URL)
exec cloudflared tunnel --url http://127.0.0.1:15722
