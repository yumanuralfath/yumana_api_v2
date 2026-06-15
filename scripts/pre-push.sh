#!/bin/bash

# Ensure SQLx metadata is up to date for offline mode
echo "Checking SQLx metadata..."

# Check if cargo-sqlx is installed
if command -v cargo-sqlx >/dev/null 2>&1; then
    # Run prepare to update metadata
    # We use --workspace to cover all crates and pass --all-targets to include tests
    if cargo sqlx prepare --workspace -- --all-targets --all-features; then
        # Check if there are changes in the .sqlx directory
        if ! git diff --exit-code .sqlx >/dev/null 2>&1; then
            echo "❌ Error: SQLx metadata was out of date and has been updated."
            echo "Please commit the changes in the '.sqlx/' directory before pushing."
            exit 1
        fi
        echo "✅ SQLx metadata is up to date."
    else
        echo "❌ Error: 'cargo sqlx prepare' failed. Please ensure your database is running and DATABASE_URL is set."
        exit 1
    fi
else
    echo "⚠️  Warning: 'cargo-sqlx' not found. Skipping metadata check."
    echo "It is recommended to install it: cargo install sqlx-cli"
fi

echo "Running local tests before pushing..."

# Run cargo test
cargo test

# Capture the exit code
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "❌ Tests failed! Push aborted."
    exit 1
fi

echo "✨ All checks passed! Proceeding with push..."
exit 0
