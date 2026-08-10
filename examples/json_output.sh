#!/bin/bash
# Example: Capturing statistics in JSON format
# =============================================
# This script demonstrates how to capture detailed statistics
# in JSON format for analysis and logging.

TARGET_URL="http://localhost:8080"
OUTPUT_FILE="torshammer_stats.json"

echo "Capturing JSON statistics to $OUTPUT_FILE"
echo "Target: $TARGET_URL"
echo ""

# Run with JSON output and redirect to file
torshammer -u "$TARGET_URL" \
    -c 256 \
    -d 60 \
    --json > "$OUTPUT_FILE"

echo "Statistics captured to $OUTPUT_FILE"
echo ""
echo "Sample JSON structure:"
echo '{"connections":256,"active":256,"peak_active":256,"completed":12,"errors":0,"bytes_sent":452000,"bytes_received":0,"sent_bytes_per_sec":7533,"uptime":60.0}'
echo ""

# You can analyze the JSON output with tools like jq:
# cat "$OUTPUT_FILE" | jq '.'
# cat "$OUTPUT_FILE" | jq '.peak_active'
# cat "$OUTPUT_FILE" | jq '.errors'

# Explanation:
# --json: Emit newline-delimited JSON statistics instead of terminal output
# > file: Redirect output to a file for later analysis
# -d 60: Run for 60 seconds then stop automatically
