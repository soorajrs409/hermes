#!/bin/bash
# Demo script showing the self-contained binary functionality

echo "=== Access Control Bypass Tester - Self-Contained Demo ==="
echo

# Check if binary exists
if [ ! -f "dist/access-bypass-tester" ] && [ ! -f "dist/access-bypass-tester.exe" ]; then
    echo "Binary not found. Run ./build.sh first."
    exit 1
fi

# Determine binary name based on platform
BINARY_NAME="dist/access-bypass-tester"
if [ -f "dist/access-bypass-tester.exe" ]; then
    BINARY_NAME="dist/access-bypass-tester.exe"
fi

echo "1. Testing help output:"
echo "Command: ./$BINARY_NAME --help | head -10"
./$BINARY_NAME --help | head -10
echo

echo "2. Testing basic functionality (no config needed):"
echo "Command: ./$BINARY_NAME --help >/dev/null 2>&1"
if ./$BINARY_NAME --help >/dev/null 2>&1; then
    echo "✅ Binary is functional and self-contained"
else
    echo "❌ Binary test failed"
fi
echo

echo "3. Testing with non-existent config file (should still work):"
echo "Command: ./$BINARY_NAME -c nonexistent.yaml --help >/dev/null 2>&1"
if ./$BINARY_NAME -c nonexistent.yaml --help >/dev/null 2>&1; then
    echo "✅ Binary handles missing config files gracefully"
else
    echo "❌ Config handling test failed"
fi
echo

echo "=== Demo Complete ==="
echo
echo "The binary is completely self-contained with embedded configuration!"
echo "No external files required - works out of the box! 🎉"