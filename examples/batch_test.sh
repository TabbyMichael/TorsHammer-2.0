#!/bin/bash
# Example: Batch testing multiple targets
# ======================================
# This script demonstrates how to test multiple targets
# from a targets file, either sequentially or in parallel.

TARGETS_FILE="targets.txt"
CONCURRENCY=128
DURATION=30
MODE="slow-post"

echo "Batch testing configuration"
echo "==========================="
echo "Targets file: $TARGETS_FILE"
echo "Concurrency: $CONCURRENCY"
echo "Duration per target: $DURATION seconds"
echo "Mode: $MODE"
echo ""

# Check if targets file exists
if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: $TARGETS_FILE not found!"
    echo "Please create the file with one target URL per line."
    exit 1
fi

# Count targets
TARGET_COUNT=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l)
echo "Found $TARGET_COUNT targets to test"
echo ""

# Sequential testing (one after another)
echo "Starting sequential testing..."
echo "================================"

while IFS= read -r target; do
    # Skip comments and empty lines
    if [[ "$target" =~ ^# ]] || [[ -z "$target" ]]; then
        continue
    fi

    echo "Testing: $target"
    torshammer -u "$target" \
        -c "$CONCURRENCY" \
        -d "$DURATION" \
        -m "$MODE" \
        -q  # Quiet mode to reduce output clutter
    echo "Completed: $target"
    echo ""
done < "$TARGETS_FILE"

echo "Batch testing completed!"
echo "Tested $TARGET_COUNT targets"

# Alternative: Parallel testing (all at once)
# Uncomment the section below for parallel testing
# ================================================
# echo "Starting parallel testing..."
# echo "============================"
#
# while IFS= read -r target; do
#     if [[ "$target" =~ ^# ]] || [[ -z "$target" ]]; then
#         continue
#     fi
#
#     torshammer -u "$target" \
#         -c "$CONCURRENCY" \
#         -d "$DURATION" \
#         -m "$MODE" \
#         -q &
# done < "$TARGETS_FILE"
#
# # Wait for all background jobs to complete
# wait
# echo "Parallel testing completed!"

# Explanation:
# Sequential testing: Tests one target at a time (safer, easier to monitor)
# Parallel testing: Tests all targets simultaneously (faster but more intense)
# -q: Quiet mode suppresses live status line for cleaner batch output
