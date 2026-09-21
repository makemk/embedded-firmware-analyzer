#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo " Embedded Firmware Analyzer - Isolated Environment Setup"
echo "======================================================================"

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 could not be found."
    exit 1
fi

echo "[1/2] Creating isolated Python virtual environment (.venv)..."
if [ ! -f ".venv/bin/python" ]; then
    python3 -m venv .venv
fi

echo "[2/2] Installing isolated dependencies..."
.venv/bin/python -m pip install --upgrade pip --quiet
.venv/bin/python -m pip install -r requirements.txt --quiet

echo ""
echo "======================================================================"
echo " Setup Complete! You can run:"
echo "   ./run_gate.sh --workspace <path_to_firmware>"
echo "======================================================================"

