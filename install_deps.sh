#!/bin/bash
# Install Python dependencies.
# Tries an online install first; falls back to the bundled wheels in `vendor/`.
# Usage: bash install_deps.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

if [ ! -f "$REQ_FILE" ]; then
    echo "Error: requirements.txt not found in $SCRIPT_DIR"
    exit 1
fi

echo "Attempting online install from PyPI..."
if pip install -r "$REQ_FILE"; then
    echo "Installed dependencies from PyPI."
    exit 0
fi

echo "Online install failed or offline. Falling back to bundled wheels in vendor/" 
if [ ! -d "$VENDOR_DIR" ]; then
    echo "Error: vendor/ directory not found. Cannot install dependencies." >&2
    exit 1
fi

echo "Installing dependencies from vendor/ ..."
pip install --no-index --find-links "$VENDOR_DIR" -r "$REQ_FILE"
echo "Done."
