#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT/backend"

exec "$ROOT/backend/.venv/bin/mitmweb" \
  --listen-host 127.0.0.1 \
  --listen-port 8080 \
  --web-host 127.0.0.1 \
  --web-port 8081 \
  -s "$ROOT/proxy/ai_guardrail_proxy.py"
