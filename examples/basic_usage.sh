#!/bin/bash
# Basic usage example for Tor's Hammer 2.0
# ========================================
# This script demonstrates the most common use case: testing a target
# with default settings (slow-post mode, 256 connections).

# Make sure torshammer is installed: pip install -e .

# Replace with your authorized target URL
TARGET_URL="http://localhost:8080"

echo "Running basic slow-post attack against $TARGET_URL"
echo "Press Ctrl-C to stop"
echo ""

torshammer -u "$TARGET_URL"

# Explanation:
# -u: Target URL (required)
# Default: slow-post mode, 256 concurrent connections, unlimited duration
