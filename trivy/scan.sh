#!/bin/bash

set -e  # Exit on any error

echo "Scan the image..."

# Fix: Use proper parameter expansion for parameters > 9
IMAGE_NAME=$1
TAG=$2
PROJECT_NAME=$3
BRANCH=$4
CI_URL=$5
CVE_DB_HOST=$6
CVE_DB_USERNAME=$7
CVE_DB_PASSWORD=$8
CVE_DB_NAME=$9
ALERT_MANAGER_URL=${10}  # Fixed: Use ${10} instead of $10
ALERT_MANAGER_SECRET=${11}  # Fixed: Use ${11} instead of $11

REPORTS_DIR="reports"
DATE_TIME="$(date +%Y%m%d-%H%M%S)"
venv_name="venv_$BRANCH"

echo "=== Scan Parameters Debug ==="
echo "IMAGE_NAME: $IMAGE_NAME"
echo "TAG: $TAG"
echo "PROJECT_NAME: $PROJECT_NAME"
echo "BRANCH: $BRANCH"
echo "CI_URL: $CI_URL"
echo "CVE_DB_HOST: $CVE_DB_HOST"
echo "CVE_DB_USERNAME: $CVE_DB_USERNAME"
echo "CVE_DB_PASSWORD: [MASKED]"
echo "CVE_DB_NAME: $CVE_DB_NAME"
echo "ALERT_MANAGER_URL: $ALERT_MANAGER_URL"
echo "ALERT_MANAGER_SECRET: [MASKED]"
echo "================================"

echo "Scanning: $IMAGE_NAME:$TAG"

# Validate required parameters
if [ -z "$IMAGE_NAME" ] || [ -z "$TAG" ]; then
    echo "Error: IMAGE_NAME and TAG are required parameters"
    exit 1
fi

# Validate database parameters
if [ -z "$CVE_DB_HOST" ] || [ -z "$CVE_DB_USERNAME" ] || [ -z "$CVE_DB_PASSWORD" ] || [ -z "$CVE_DB_NAME" ]; then
    echo "Warning: Database parameters are missing or empty"
    echo "CVE_DB_HOST: ${CVE_DB_HOST:-'NOT SET'}"
    echo "CVE_DB_USERNAME: ${CVE_DB_USERNAME:-'NOT SET'}"
    echo "CVE_DB_PASSWORD: ${CVE_DB_PASSWORD:+'SET'}${CVE_DB_PASSWORD:-'NOT SET'}"
    echo "CVE_DB_NAME: ${CVE_DB_NAME:-'NOT SET'}"
fi

# Create Reports Directory if not present
if [ ! -d "$REPORTS_DIR" ]; then
    mkdir -p "$REPORTS_DIR"
    echo "Created reports directory: $REPORTS_DIR"
fi

# Check if the Trivy Package Present
if ! command -v trivy >/dev/null 2>&1; then
    echo "Error: Trivy is not installed or not in PATH."
    echo "Please install Trivy before running this job."
    exit 1 
fi

# Check Python availability
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python3 is not installed or not in PATH."
    exit 1
fi

# Setup Python Virtual Environment (inside workspace)
if [ ! -d "$venv_name" ]; then
    echo "Creating Python virtual environment: $venv_name"
    python3 -m venv "$venv_name"
fi

# Activate venv
echo "Activating virtual environment..."
source "$venv_name/bin/activate"

# Verify virtual environment is active
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Warning: Virtual environment may not be active"
else
    echo "Virtual environment active: $VIRTUAL_ENV"
fi

# Upgrade pip and install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip

# Install psycopg2 for PostgreSQL connectivity
echo "Installing required Python packages..."
pip install psycopg2-binary requests

# Check if requirements.txt exists and install
if [ -f "requirements.txt" ]; then
    echo "Installing from requirements.txt..."
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found, skipping dependency installation"
fi

# Test database connectivity before scan
echo "Testing database connectivity..."
python3 -c "
import sys
try:
    import psycopg2
    conn = psycopg2.connect(
        dbname='$CVE_DB_NAME',
        user='$CVE_DB_USERNAME',
        password='$CVE_DB_PASSWORD',
        host='$CVE_DB_HOST',
        port='5432',
        connect_timeout=10
    )
    print('✓ Database connection successful')
    cur = conn.cursor()
    cur.execute('SELECT version();')
    version = cur.fetchone()[0]
    print(f'PostgreSQL version: {version[:50]}...')
    conn.close()
except Exception as e:
    print(f'✗ Database connection failed: {e}')
    sys.exit(1)
" || {
    echo "Database connectivity test failed. Continuing with scan but database insertion may fail."
}

# Verify the image exists locally
if ! docker images "$IMAGE_NAME:$TAG" --format "table {{.Repository}}:{{.Tag}}" | grep -q "$TAG"; then
    echo "Error: Docker image $IMAGE_NAME:$TAG not found locally"
    echo "Available images:"
    docker images "$IMAGE_NAME" || echo "No images found for repository: $IMAGE_NAME"
    exit 1
fi

echo "Running Trivy security scan..."

# Run the Trivy Scan with better error handling
trivy image \
    --ignore-unfixed \
    --timeout 10m \
    --format json \
    --output "$REPORTS_DIR/scan-report-$TAG.json" \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --exit-code 0 \
    "$IMAGE_NAME:$TAG"

TRIVY_EXIT_CODE=$?

if [ $TRIVY_EXIT_CODE -ne 0 ]; then
    echo "Warning: Trivy scan completed with exit code $TRIVY_EXIT_CODE"
fi

JSON_PATH="$REPORTS_DIR/scan-report-$TAG.json"

# Verify scan report was generated
if [ ! -f "$JSON_PATH" ]; then
    echo "Error: Scan report not generated at $JSON_PATH"
    exit 1
fi

echo "Scan report generated: $JSON_PATH"
REPORT_SIZE=$(du -h "$JSON_PATH" | cut -f1)
echo "Report size: $REPORT_SIZE"

# Validate JSON file
echo "Validating JSON report..."
if python3 -c "import json; json.load(open('$JSON_PATH'))" 2>/dev/null; then
    echo "✓ JSON report is valid"
else
    echo "✗ JSON report is invalid"
    exit 1
fi

# Add build_id to output for pipeline tracking
BUILD_ID=$(basename "$CI_URL" | grep -o '[0-9]*' | tail -1)
if [ -z "$BUILD_ID" ]; then
    BUILD_ID="$TAG"
fi
echo "build_id: $BUILD_ID"

# Check if report.py exists
if [ ! -f "./trivy/report.py" ]; then
    echo "Error: report.py not found at ./trivy/report.py"
    echo "Current directory: $(pwd)"
    echo "Contents of trivy directory:"
    ls -la trivy/ || echo "trivy directory not found"
    exit 1
fi

# Make report.py executable
chmod +x ./trivy/report.py

# Call the report.py to store data to DB
if [ -n "$CVE_DB_HOST" ] && [ -n "$CVE_DB_USERNAME" ] && [ -n "$CVE_DB_PASSWORD" ] && [ -n "$CVE_DB_NAME" ]; then
    echo "=== Calling report.py to store results in database ==="
    echo "Database: $CVE_DB_HOST/$CVE_DB_NAME"
    echo "User: $CVE_DB_USERNAME"
    echo "Report file: $JSON_PATH"
    
    # Enable debug mode for report.py
    export DEBUG=true
    
    # Set error handling for the Python script
    set +e  # Temporarily disable exit on error
    
    python3 ./trivy/report.py \
        "$JSON_PATH" \
        "$IMAGE_NAME" \
        "$TAG" \
        "$PROJECT_NAME" \
        "$CI_URL" \
        "$CVE_DB_HOST" \
        "$CVE_DB_USERNAME" \
        "$CVE_DB_PASSWORD" \
        "$CVE_DB_NAME" \
        "$ALERT_MANAGER_URL" \
        "$ALERT_MANAGER_SECRET"
    
    REPORT_EXIT_CODE=$?
    set -e  # Re-enable exit on error
    
    if [ $REPORT_EXIT_CODE -eq 0 ]; then
        echo "✓ report.py completed successfully"
    else
        echo "✗ report.py failed with exit code: $REPORT_EXIT_CODE"
        echo "This may indicate database insertion issues"
        # Don't exit here, allow the scan to complete
    fi
    
else
    echo "Skipping database storage - missing database parameters:"
    echo "CVE_DB_HOST: ${CVE_DB_HOST:-'NOT SET'}"
    echo "CVE_DB_USERNAME: ${CVE_DB_USERNAME:-'NOT SET'}"
    echo "CVE_DB_PASSWORD: ${CVE_DB_PASSWORD:+'SET'}${CVE_DB_PASSWORD:-'NOT SET'}"
    echo "CVE_DB_NAME: ${CVE_DB_NAME:-'NOT SET'}"
fi

# Deactivate virtual environment
deactivate || true

echo "Security scan completed successfully"
exit 0
