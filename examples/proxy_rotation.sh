#!/bin/bash
# Example: Using multiple proxies with rotation
# =============================================
# This script demonstrates how to use a list of proxies and
# rotate them across connections for better distribution.

TARGET_URL="http://example.com"
PROXY_FILE="proxies.txt"

echo "Using proxy rotation with proxies from $PROXY_FILE"
echo "Target: $TARGET_URL"
echo ""

# Create a sample proxy file if it doesn't exist
if [ ! -f "$PROXY_FILE" ]; then
    echo "Creating sample proxy file..."
    cat > "$PROXY_FILE" << EOF
# Example proxies - replace with your actual proxies
socks5://proxy1.example.com:1080
socks5://proxy2.example.com:1080
http://proxy3.example.com:8080
socks4://proxy4.example.com:1080
EOF
fi

# Run with proxy rotation
torshammer -u "$TARGET_URL" \
    --proxy-list "$PROXY_FILE" \
    --rotate-proxies \
    -c 512

# Explanation:
# --proxy-list: File containing one proxy URL per line
# --rotate-proxies: Randomly select a different proxy for each connection
# -c 512: Higher concurrency since we're distributing across multiple proxies
