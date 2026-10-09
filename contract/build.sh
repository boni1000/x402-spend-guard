#!/usr/bin/env bash
# Build the agentgov contract with Antelope CDT (tested with CDT 4.1).
set -euo pipefail
cd "$(dirname "$0")"
cdt-cpp -abigen -o agentgov.wasm agentgov.cpp
echo "agentgov.wasm sha256: $(sha256sum agentgov.wasm 2>/dev/null | cut -d' ' -f1 || shasum -a 256 agentgov.wasm | cut -d' ' -f1)"
