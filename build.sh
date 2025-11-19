#!/bin/bash
# Build script for Access Control Bypass Tester

set -e

echo "Building Access Control Bypass Tester..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed. Aborting."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
pip install nuitka ordered-set zstandard

# Build with Nuitka
echo "Building binary with Nuitka..."
python3 -m nuitka \
    --onefile \
    --output-filename=access-bypass-tester \
    --output-dir=dist \
    --assume-yes-for-downloads \
    --remove-output \
    --no-deployment-flag=self-execution \
    access_bypass_tester_v2.py

# Make executable
chmod +x dist/access-bypass-tester

# Test the binary
echo "Testing binary functionality..."
echo "Help output:"
./dist/access-bypass-tester --help | head -20

echo -e "\nTesting basic functionality:"
./dist/access-bypass-tester --help >/dev/null 2>&1 && echo "Binary functional test passed" || echo "Binary test failed"

echo -e "\nBuild complete! Binary available at: dist/access-bypass-tester"
echo "To install globally: sudo cp dist/access-bypass-tester /usr/local/bin/"
echo "To test: ./dist/access-bypass-tester --help"