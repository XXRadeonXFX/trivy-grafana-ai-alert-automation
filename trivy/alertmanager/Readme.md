# Azure VM Deployment Guide for Grafana & AlertManager

## Prerequisites Check

Before starting, ensure your Azure VM has:
- Docker and Docker Compose installed
- Ports 3000 (Grafana) and 8000 (AlertManager) open in Azure Network Security Group
- SSH access to your VM (4.240.98.78)

## Step 1: Connect to Your Azure VM

```bash
ssh azureuser@4.240.98.78
```

## Step 2: Install Docker and Docker Compose (if not already installed)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login again to apply docker group changes
exit
```

## Step 3: Create Project Directory

```bash
# Reconnect to VM
ssh azureuser@4.240.98.78

# Create project directory
mkdir -p ~/trivy-scanner/alertmanager
cd ~/trivy-scanner
```

## Step 4: Create the .env File

```bash
cat > .env << 'EOF'
# PostgreSQL Database
PG_DB=cve_scanner
PG_USER=postgres
PG_HOST=trivy-postgres-server.postgres.database.azure.com
PG_PORT=5432
PG_PASS=XXXXXXXXXXXX

POSTGRES_HOST=trivy-postgres-server.postgres.database.azure.com
POSTGRES_DB=cve_scanner
POSTGRES_USER=postgres
POSTGRES_PASSWORD=XXXXXXXXXXXX

# SMTP Email Settings
SMTP_FROM_EMAIL=prince.beats01@gmail.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=prince.beats01@gmail.com
SMTP_PASS=XXXXXXXXXXX
ALERT_TO_EMAILS=prince.thakurXXXXX@gmail.com

# Grafana Dashboard links
GRAFANA_URL=http://4.240.98.78:3000
BUILD_DASHBOARD_UID=build-dashboard

# AI Keys
GEMINI_API_KEY=
OPENAI_API_KEY=
#AI_API_KEY=

# API Secret
WEBHOOK_API_SECRET=yourapisecret
EOF
```

## Step 5: Create AlertManager Application Files

### Create requirements.txt
```bash
mkdir -p alertmanager
cat > alertmanager/requirements.txt << 'EOF'
fastapi
uvicorn[standard]
psycopg2-binary
python-dotenv
google-genai
openai
beautifulsoup4
EOF
```

### Create Dockerfile
```bash
cat > alertmanager/Dockerfile << 'EOF'
# Use official Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI with Uvicorn and enable auto-reload
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EOF
```

### Copy the app.py file
```bash
# You'll need to copy the app.py content from your documentation
# Here's a simplified version for deployment:

cat > alertmanager/app.py << 'EOF'
#!/usr/bin/env python3
from fastapi import FastAPI, Request, HTTPException, status, Header
from pydantic import BaseModel
import psycopg2
import psycopg2.extras
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import date, timedelta
from google import genai
from typing import Optional
import json
import openai
from bs4 import BeautifulSoup

app = FastAPI()

# Environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GRAFANA_URL = os.getenv("GRAFANA_URL")
BUILD_DASHBOARD_UID = os.getenv("BUILD_DASHBOARD_UID")
WEBHOOK_API_SECRET = os.getenv("WEBHOOK_API_SECRET")

# PostgreSQL Connection
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("PG_DB", "cve_db"),
        user=os.getenv("PG_USER", "postgres"),
        password=os.getenv("PG_PASS", "postgres"),
        host=os.getenv("PG_HOST", "localhost"),
        port=os.getenv("PG_PORT", "5432")
    )

@app.get("/")
def read_root():
    return {"message": "AlertManager API is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/email-test")
def test_email():
    try:
        SMTP_HOST = os.getenv("SMTP_HOST")
        SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
        SMTP_USER = os.getenv("SMTP_USER")
        SMTP_PASS = os.getenv("SMTP_PASS")
        ALERT_TO_EMAILS = os.getenv("ALERT_TO_EMAILS", "").split(",")
        SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")

        msg = MIMEText("✅ Test email from FastAPI AlertManager", "plain")
        msg["Subject"] = "Test Alert from Azure VM"
        msg["From"] = SMTP_FROM_EMAIL 
        msg["To"] = ", ".join(ALERT_TO_EMAILS)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], ALERT_TO_EMAILS, msg.as_string())

        return {"status": "Email sent successfully!"}
    except Exception as e:
        return {"error": str(e)}

# Add more endpoints from your app.py as needed
EOF
```

## Step 6: Create Docker Compose File

```bash
cat > docker-compose.yaml << 'EOF'
version: '3.8'

services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana_dashboard
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SERVER_ROOT_URL=http://4.240.98.78:3000
      - GF_SMTP_ENABLED=true
      - GF_SMTP_HOST=smtp.gmail.com:587
      - GF_SMTP_USER=prince.beats01@gmail.com
      - GF_SMTP_PASSWORD=XXXXXXXXXX
      - GF_SMTP_FROM_ADDRESS=prince.beats01@gmail.com
      - GF_SMTP_FROM_NAME=Grafana Alerts
      - GF_SMTP_SKIP_VERIFY=true
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123
    networks:
      - monitoring_network

  alert-service:
    build:
      context: ./alertmanager
      dockerfile: Dockerfile
    container_name: alert-service
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      # PostgreSQL settings
      PG_DB: ${PG_DB}
      PG_USER: ${PG_USER}
      PG_PASS: ${PG_PASS}
      PG_HOST: ${PG_HOST}
      PG_PORT: ${PG_PORT}

      # SMTP settings
      SMTP_FROM_EMAIL: ${SMTP_FROM_EMAIL}
      SMTP_HOST: ${SMTP_HOST}
      SMTP_PORT: ${SMTP_PORT}
      SMTP_USER: ${SMTP_USER}
      SMTP_PASS: ${SMTP_PASS}
      ALERT_TO_EMAILS: ${ALERT_TO_EMAILS}

      # Grafana Dashboard links
      GRAFANA_URL: ${GRAFANA_URL}
      BUILD_DASHBOARD_UID: ${BUILD_DASHBOARD_UID}

      # AI Keys
      GEMINI_API_KEY: ${GEMINI_API_KEY}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      AI_API_KEY: ${AI_API_KEY}

      # API Secret
      WEBHOOK_API_SECRET: ${WEBHOOK_API_SECRET}
    networks:
      - monitoring_network
    depends_on:
      - grafana

volumes:
  grafana_data:

networks:
  monitoring_network:
    driver: bridge
EOF
```

## Step 7: Configure Azure Network Security Group

Add inbound rules for:
- Port 3000 (Grafana) - Source: Any, Destination: 4.240.98.78:3000
- Port 8000 (AlertManager) - Source: Any, Destination: 4.240.98.78:8000

```bash
# If you have Azure CLI installed locally, run:
# az network nsg rule create --resource-group <your-rg> --nsg-name <your-nsg> --name AllowGrafana --priority 1000 --source-address-prefixes '*' --destination-port-ranges 3000 --protocol Tcp
# az network nsg rule create --resource-group <your-rg> --nsg-name <your-nsg> --name AllowAlertManager --priority 1001 --source-address-prefixes '*' --destination-port-ranges 8000 --protocol Tcp
```

## Step 8: Deploy Services

```bash
# Make sure you're in the project directory
cd ~/trivy-scanner

# Start the services
docker-compose up -d

# Check if services are running
docker-compose ps

# View logs if needed
docker-compose logs grafana
docker-compose logs alert-service
```

## Step 9: Test Your Deployment

### Test AlertManager
```bash
# Test health endpoint
curl http://4.240.98.78:8000/health

# Test email functionality
curl http://4.240.98.78:8000/email-test
```

### Access Grafana
- Open browser: http://4.240.98.78:3000
- Login: admin / admin123
- Change password when prompted

## Step 10: Configure Grafana Data Source

1. Go to **Configuration** → **Data Sources**
2. Add **PostgreSQL** data source with these settings:
   - Host: `trivy-postgres-server.postgres.database.azure.com:5432`
   - Database: `cve_scanner`
   - User: `postgres`
   - Password: `1029384756!Sound`
   - SSL Mode: `require`

## Step 11: Import Dashboards

1. Go to **+** → **Import**
2. Upload the JSON files from your `grafana-dashboards/` folder
3. Select the PostgreSQL data source when prompted

## Troubleshooting Commands

```bash
# Check running containers
docker ps

# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Stop all services
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Check Azure VM firewall (Ubuntu)
sudo ufw status
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
```

## URLs After Deployment

- **Grafana**: http://4.240.98.78:3000 (admin/admin123)
- **AlertManager API**: http://4.240.98.78:8000
- **AlertManager Health**: http://4.240.98.78:8000/health
- **Email Test**: http://4.240.98.78:8000/email-test

## Security Notes

1. Change default Grafana password immediately
2. Consider using environment variables for sensitive data
3. Set up proper SSL certificates for production
4. Restrict NSG rules to specific IP ranges if needed

Your deployment should now be ready! The services will automatically restart if the VM reboots thanks to the `restart: unless-stopped` policy.
