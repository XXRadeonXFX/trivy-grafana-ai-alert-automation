#!/bin/bash

echo "Scan the image..."

IMAGE_NAME=$1
TAG=$2
PROJECT_NAME=$3
BRANCH=$4
CI_URL=$5
CVE_DB_HOST=$6
CVE_DB_USERNAME=$7
CVE_DB_PASSWORD=$8
CVE_DB_NAME=$9
ALERT_MANAGER_URL=$10
ALERT_MANAGER_SECRET=$11
REPORTS_DIR="reports"
DATE_TIME="$(date +%Y%m%d-%H%M%S)"
venv_name="venv_$BRANCH"

echo "$IMAGE_NAME:$TAG"

# Create Reports Directory if not present
if [ ! -d "$REPORTS_DIR" ]; then
    mkdir "$REPORTS_DIR"
fi

# Setup Python Virtual Environment (inside workspace)
if [ ! -d "$venv_name" ]; then
    python3 -m venv "$venv_name"
fi

# Check if the Trivy Package Present
if ! command -v trivy >/dev/null 2>&1; then
    echo "❌ Error: Trivy is not installed or not in PATH."
    echo "Please install Trivy before running this job."
    exit 1 
fi

# Activate venv
source "$venv_name/bin/activate"

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run the Trivy Scan
trivy image \
    --ignore-unfixed \
    --ignorefile ./trivy/.trivyignore \
    --timeout 10m \
    --format json \
    --output "$REPORTS_DIR/scan-report-$TAG.json" \
    "$IMAGE_NAME:$TAG"

JSON_PATH="$REPORTS_DIR/scan-report-$TAG.json"

# Call the report.py to store data to DB
./trivy/report.py "$JSON_PATH" "$IMAGE_NAME" "$TAG" "$PROJECT_NAME" "$CI_URL" "$CVE_DB_HOST" "$CVE_DB_USERNAME" "$CVE_DB_PASSWORD" "$CVE_DB_NAME" "$ALERT_MANAGER_URL" "$ALERT_MANAGER_SECRET"