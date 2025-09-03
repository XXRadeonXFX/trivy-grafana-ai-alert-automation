#!/bin/sh

# Check if we're running tests
if [ "$RUN_TESTS" = "true" ]; then
    echo "Running tests..."
    python -m pytest
else
    echo "Starting Flask application..."
    python app.py
fi 