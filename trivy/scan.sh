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

echo "Scanning: $IMAGE_NAME:$TAG"

# Validate required parameters
if [ -z "$IMAGE_NAME" ] || [ -z "$TAG" ]; then
    echo "Error: IMAGE_NAME and TAG are required parameters"
    exit 1
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

# Setup Python Virtual Environment (inside workspace)
if [ ! -d "$venv_name" ]; then
    echo "Creating Python virtual environment: $venv_name"
    python3 -m venv "$venv_name"
fi

# Activate venv
echo "Activating virtual environment..."
source "$venv_name/bin/activate"

# Upgrade pip and install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip

# Check if requirements.txt exists
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found, skipping dependency installation"
fi

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
echo "Report size: $(du -h "$JSON_PATH" | cut -f1)"

# Add build_id to output for pipeline tracking
echo "build_id: $(basename "$CI_URL" | grep -o '[0-9]*' | tail -1)" || echo "build_id: $TAG"

# Call the report.py to store data to DB (if it exists and parameters are provided)
if [ -f "./trivy/report.py" ] && [ -n "$CVE_DB_HOST" ]; then
    echo "Calling report.py to store results in database..."
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
else
    echo "Skipping database storage (report.py not found or database parameters missing)"
fi

# Deactivate virtual environment
deactivate || true

echo "Security scan completed successfully"
exit 0
