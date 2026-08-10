#!/bin/bash
# Example: Testing HTTPS targets
# ===============================
# This script demonstrates how to test HTTPS endpoints with
# proper TLS handling and SNI support.

TARGET_URL="https://example.com/api"

echo "Testing HTTPS target with TLS"
echo "Target: $TARGET_URL"
echo ""

# Basic HTTPS test (with certificate verification)
echo "1. Testing with certificate verification..."
torshammer -u "$TARGET_URL" -c 128 -d 30
echo ""

# HTTPS with self-signed certificates (skip verification)
echo "2. Testing with self-signed certificates (no verification)..."
torshammer -u "$TARGET_URL" -c 128 -d 30 --ssl-no-verify
echo ""

# HTTPS with custom User-Agent list
echo "3. Testing with custom User-Agent list..."
torshammer -u "$TARGET_URL" \
    -c 128 \
    -d 30 \
    --user-agents user-agents.txt

# Explanation:
# HTTPS is automatically detected from the URL scheme
# --ssl-no-verify: Skip TLS certificate validation (use for testing with self-signed certs)
# --user-agents: Load custom User-Agent strings from file
