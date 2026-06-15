#!/bin/bash

# Path to the hooks directory
HOOK_DIR=".git/hooks"
PRE_PUSH_HOOK="$HOOK_DIR/pre-push"

# Copy the script to the hooks directory
cp scripts/pre-push.sh "$PRE_PUSH_HOOK"

# Make the hook executable
chmod +x "$PRE_PUSH_HOOK"

echo "Git pre-push hook installed successfully!"
