#!/bin/bash

echo "Running local tests before pushing..."

# Run cargo test
cargo test

# Capture the exit code
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "Tests failed! Push aborted."
    exit 1
fi

echo "Tests passed! Proceeding with push..."
exit 0
