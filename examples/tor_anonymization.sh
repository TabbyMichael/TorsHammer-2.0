#!/bin/bash
# Example: Using Tor for anonymization
# =====================================
# This script demonstrates how to route traffic through Tor
# to maintain anonymity during authorized testing.

# Make sure Tor is running: tor
# Default Tor SOCKS5 proxy: 127.0.0.1:9050

TARGET_URL="http://example.com"

echo "Routing traffic through Tor (127.0.0.1:9050)"
echo "Target: $TARGET_URL"
echo ""

# Simple Tor routing
torshammer -u "$TARGET_URL" --tor

# Alternative: Using a custom Tor endpoint
# torshammer -u "$TARGET_URL" --proxy socks5://127.0.0.1:9050

# Explanation:
# --tor: Route through Tor at default SOCKS5 port (127.0.0.1:9050)
# --proxy: Specify a custom proxy URL (SOCKS5, SOCKS4, or HTTP)
