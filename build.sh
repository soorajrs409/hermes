#!/bin/bash
# Build script for Access Control Bypass Tester

set -e

echo "Building Access Control Bypass Tester..."

# Check if Python 3 is available (try python3 first, then python)
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null && python --version 2>&1 | grep -q "Python 3"; then
    PYTHON_CMD="python"
else
    echo "Python 3 is required but not installed. Aborting."
    exit 1
fi

echo "Using Python command: $PYTHON_CMD"

# Determine pip command
PIP_CMD=""
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    echo "pip is required but not installed. Aborting."
    exit 1
fi

echo "Using pip command: $PIP_CMD"

# Install dependencies
echo "Installing dependencies..."
$PIP_CMD install -r requirements.txt
$PIP_CMD install nuitka ordered-set zstandard

# Build with Nuitka (static linking for better compatibility)
echo "Building binary with Nuitka..."
$PYTHON_CMD -m nuitka \
    --onefile \
    --output-filename=access-bypass-tester \
    --output-dir=dist \
    --assume-yes-for-downloads \
    --remove-output \
    --no-deployment-flag=self-execution \
    --static-libpython=yes \
    --linux-onefile-icon=access_bypass_tester_v2.py \
    access_bypass_tester_v2.py

# Make executable (skip on Windows)
if [[ "$OSTYPE" != "msys" ]] && [[ "$OSTYPE" != "win32" ]]; then
    chmod +x dist/access-bypass-tester
fi

# Test the binary
echo "Testing binary functionality..."
echo "Help output:"
./dist/access-bypass-tester --help | head -20

echo -e "\nTesting basic functionality:"
./dist/access-bypass-tester --help >/dev/null 2>&1 && echo "Binary functional test passed" || echo "Binary test failed"

echo -e "\nBuild complete! Binary available at: dist/access-bypass-tester"
echo "To install globally: sudo cp dist/access-bypass-tester /usr/local/bin/"
echo "To test: ./dist/access-bypass-tester --help"