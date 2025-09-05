#!/usr/bin/env python3
from fastapi import FastAPI, Request, HTTPException, status, Header,UploadFile, File
from pydantic import BaseModel
import psycopg2
import psycopg2.extras  # DictCursor, RealDictCursor, etc.

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

#---------- Grafana Details ---------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GRAFANA_URL= os.getenv("GRAFANA_URL")
BUILD_DASHBOARD_UID= os.getenv("BUILD_DASHBOARD_UID")
WEBHOOK_API_SECRET= os.getenv("WEBHOOK_API_SECRET")

# ---------- PostgreSQL Connection ----------
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("PG_DB", "cve_db"),
        user=os.getenv("PG_USER", "postgres"),
        password=os.getenv("PG_PASS", "postgres"),
        host=os.getenv("PG_HOST", "localhost"),
        port=os.getenv("PG_PORT", "5432")
    )


# ---------- Send Email ----------

def send_email(subject,html_content):
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT"))
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")  # must be verified in SES
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    ALERT_TO_EMAILS = os.getenv("ALERT_TO_EMAILS", "").split(",")

    if not SMTP_FROM_EMAIL or not ALERT_TO_EMAILS:
        raise ValueError(f"Missing required email env vars. From: {SMTP_FROM_EMAIL}, To: {ALERT_TO_EMAILS}")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM_EMAIL
    msg["Sender"] = SMTP_FROM_EMAIL
    msg["To"] = ", ".join(ALERT_TO_EMAILS)

    # plain + html
    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM_EMAIL, ALERT_TO_EMAILS, msg.as_string())


# ---------- Generate HTML Summary ----------
# Detailed Report

def generate_detailed_report_styled(type):
    conn = get_db_connection()
    cur = conn.cursor()
    html = ""

    # 📅 Select date range & heading
    if type == "daily":
        today = date.today()
        end_date = today - timedelta(days=1)
        html += f"""
        <h2 style="color:#2F4F4F; font-family:Arial; text-align:center;">
            Daily Vulnerability & Secrets Report <br>
            <span style="font-size:14px; color:#666;">For {end_date}</span>
        </h2>
        """
        total_days = "1"
    else:
        today = date.today()
        start_date = today - timedelta(days=7)
        end_date = today - timedelta(days=1)
        html += f"""
        <h2 style="color:#2F4F4F; font-family:Arial; text-align:center;">
            Weekly Vulnerability & Secrets Report <br>
            <span style="font-size:14px; color:#666;">For {start_date} → {end_date}</span>
        </h2>
        """
        total_days = "7"

    # SQL query
    cur.execute(f"""
        SELECT 
            br.project,
            br.id AS build_id,
            br.timestamp::date AS build_date,
            COALESCE(COUNT(DISTINCT ts.id), 0) AS secrets_exposed,
            COALESCE(SUM(CASE WHEN tr.severity = 'CRITICAL' AND tr.is_exception=0 THEN 1 ELSE 0 END), 0) AS critical_count,
            COALESCE(SUM(CASE WHEN tr.severity = 'HIGH' AND tr.is_exception=0 THEN 1 ELSE 0 END), 0) AS high_count,
            COALESCE(SUM(CASE WHEN tr.severity = 'MEDIUM' AND tr.is_exception=0 THEN 1 ELSE 0 END), 0) AS medium_count,
            COALESCE(SUM(CASE WHEN tr.severity = 'LOW' AND tr.is_exception=0 THEN 1 ELSE 0 END), 0) AS low_count,
            COALESCE(SUM(CASE WHEN tr.is_exception = 1 THEN 1 ELSE 0 END), 0) AS approved_exceptions
        FROM build_reports br
        LEFT JOIN trivy_results tr ON tr.build_id = br.id
        LEFT JOIN trivy_secrets ts ON ts.build_id = br.id
        WHERE br.timestamp >= CURRENT_DATE - INTERVAL '{total_days} day'
          AND br.timestamp < CURRENT_DATE
        GROUP BY br.project, br.id, br.timestamp
        ORDER BY br.project, br.timestamp DESC;
    """)

    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Group by project
    project_data = {}
    totals = {
        "secrets": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "exceptions": 0
    }

    for row in rows:
        project = row[0]
        if project not in project_data:
            project_data[project] = []
        project_data[project].append(row)

        # update totals
        totals["secrets"] += row[3]
        totals["critical"] += row[4]
        totals["high"] += row[5]
        totals["medium"] += row[6]
        totals["low"] += row[7]
        totals["exceptions"] += row[8]

    # 🎨 CSS Styles
    html += """
    <style>
        table {
            width: 95%;
            margin: 10px auto;
            border-collapse: collapse;
            font-family: Arial, sans-serif;
            font-size: 14px;
        }
        th {
            background: #1f2937;
            color: white;
            padding: 8px;
            text-align: center;
        }
        td {
            text-align: center;
            padding: 6px;
            border: 1px solid #ddd;
        }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #f1f5f9; }
        .critical { background:#b91c1c; color:white; font-weight:bold; }
        .high { background:#f97316; color:white; }
        .medium { background:#eab308; }
        .low { background:#22c55e; color:white; }
        .exceptions { background:#6b7280; color:white; }
        .secrets { background:#0ea5e9; color:white; }
        h3 {
            font-family: Arial, sans-serif;
            color: #111827;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 4px;
            margin-top: 30px;
        }
        h2 {
            margin-bottom: 20px;
        }
        a {
            color: #2563eb;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover { text-decoration: underline; }
    </style>
    """

    # 🔹 Summary Table (All Projects)
    html += """
    <h3>📊 Summary (All Projects)</h3>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
        <tr style="background:#f2f2f2;">
            <th class="secrets">Secrets</th>
            <th class="critical">Critical</th>
            <th class="high">High</th>
            <th class="medium">Medium</th>
            <th class="low">Low</th>
            <th class="exceptions">Exceptions</th>
        </tr>
        <tr>
            <td>{secrets}</td>
            <td class="critical">{critical}</td>
            <td class="high">{high}</td>
            <td class="medium">{medium}</td>
            <td class="low">{low}</td>
            <td class="exceptions">{exceptions}</td>
        </tr>
    </table><br/>
    """.format(**totals)

    # 🔹 Per-project Detailed Tables
    for project, builds in project_data.items():
        html += f"<h3>Project: {project}</h3>"
        html += """
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background:#f2f2f2;">
                <th>Build ID</th>
                <th>Build Date</th>
                <th class="secrets">Secrets</th>
                <th class="critical">Critical</th>
                <th class="high">High</th>
                <th class="medium">Medium</th>
                <th class="low">Low</th>
                <th class="exceptions">Exceptions</th>
                <th>Action</th>
            </tr>
        """
        for (_, build_id, build_date, secrets, critical, high, medium, low, exceptions) in builds:
            link = f"{GRAFANA_URL}/d/{BUILD_DASHBOARD_UID}?var-build_id={build_id}"
            html += f"""
            <tr>
                <td>{build_id}</td>
                <td>{build_date}</td>
                <td>{secrets}</td>
                <td class="critical">{critical}</td>
                <td class="high">{high}</td>
                <td class="medium">{medium}</td>
                <td class="low">{low}</td>
                <td class="exceptions">{exceptions}</td>
                <td><a href="{link}" target="_blank">View Report</a></td>
            </tr>
            """
        html += "</table><br/>"

    return html

# ---------- Webhook Endpoint ----------
@app.post("/trigger-weekly-alert")
async def trigger_alert(request: Request, api_secret: str = Header(None)):
    """
    Trigger this endpoint via Grafana webhook or manually.
    Sends an email summary of vulnerabilities from yesterday.
    """
    if api_secret != WEBHOOK_API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    try:

        # 📅 Date range for last 7 days
        today = date.today()
        start_date = today - timedelta(days=7)
        end_date = today - timedelta(days=1)
        subject = f"Weekly Vulnerability Summary ({start_date} to {end_date})"
        html_summary = generate_detailed_report_styled("weekly")
        send_email(subject,html_summary)
        return {"status": "success", "message": "Email sent."}
    except Exception as e:
        return {"status": "errors", "message": str(e)}


# ---------- Daily Alert ----------
@app.post("/trigger-daily-alert")
async def trigger_alert(request: Request, api_secret: str = Header(None)):
    """
    Trigger this endpoint via Grafana webhook or manually.
    Sends an email summary of vulnerabilities from yesterday.
    """
    if api_secret != WEBHOOK_API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    try:
        today = date.today()
        end_date = today - timedelta(days=1)
        subject = f"Daily Vulnerability Summary ({end_date})"
        html_summary = generate_detailed_report_styled("daily")
        send_email(subject,html_summary)
        return {"status": "success", "message": "Email sent."}
    except Exception as e:
        return {"status": "errors", "message": str(e)}

#------ Test Alert ----------
@app.get("/email-test")
def trigger():
    try:
        SMTP_HOST = os.getenv("SMTP_HOST")
        SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
        SMTP_USER = os.getenv("SMTP_USER")
        SMTP_PASS = os.getenv("SMTP_PASS")
        ALERT_TO_EMAILS = os.getenv("ALERT_TO_EMAILS", "").split(",")
        SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")

        msg = MIMEText("✅ Test email from FastAPI", "plain")
        msg["Subject"] = "Test Alert"
        msg["From"] = SMTP_FROM_EMAIL 
        msg["To"] = ", ".join(ALERT_TO_EMAILS)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.set_debuglevel(1)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)  # SES SMTP creds
            server.sendmail(msg["From"], ALERT_TO_EMAILS, msg.as_string())

        return {"status": "Email sent!"}
    except Exception as e:
        return {"error": str(e)}

#--------- AI Suggestion ----------#
class PromptRequest(BaseModel):
    jenkins_build_number: int = Field(..., alias="build_id")
    ai_engine: str
    model: str

    class Config:
        allow_population_by_field_name = True

@app.post("/generate-ai-suggestion")
async def generate_text(request: PromptRequest,api_secret: str = Header(None)):
    if api_secret != WEBHOOK_API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    try:
        ai_engine = request.ai_engine
        model= request.model
        jenkins_build_number = request.jenkins_build_number 

        print(f"Processing AI suggestion request for Jenkins Build: {jenkins_build_number}")

        # Count the Vulnerability
        check = check_vulnerability_count(jenkins_build_number)
        print(f"Vulnerability count check returned: {check}")

        if check >0:

            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            
            # Fixed query to use the correct column names
            select_query = """
            SELECT id, project, image, tag, ci_url
            FROM build_reports
            WHERE jenkins_build_number = %s;
            """
            cur.execute(select_query, (jenkins_build_number,))
            row = cur.fetchone()

            if not row:
                cur.close()
                conn.close()
                print(f"No build found with id {jenkins_build_number}")
                return {
                    "jenkins_build_number": request.jenkins_build_number,
                    "ai_engine": request.ai_engine,
                    "html_content": f"Build {jenkins_build_number} not found in database"
                }

            tag = row['tag']
            ci_url = row['ci_url']

            # Get the CVE lists
            cve_name = get_vuln_ids(jenkins_build_number)
            print(f"Retrieved CVEs: {cve_name[:100]}...")

            project_name = row['project']
            image_name= str(row['image'])+":"+str(row['tag'])
            
            prompt = f"""
                You are a Security and DevSecOps expert. I am using the docker for my project :

                I ran a vulnerability scan and found these CVEs on my docker image:
                {cve_name}

                Your task:
                1. For each unique CVE, give a short, simple explanation of the issue.
                2. Provide the exact fix command (e.g., apt-get install <package>=<fixed-version> or pip install <package>==<version>).
                3. Group CVEs if the same package upgrade fixes multiple issues.
                4. Show HIGH severity CVEs and their fixes first.
                5. Output should ONLY be in bullet points:
                - CVE-ID → Short explanation → Fix command
                6. At the end, provide a single Dockerfile snippet with all necessary changes applied.

                👉 Example of expected response format:
                <h4>HIGH severity CVEs   </h4>
                <ul>
                <li>CVE-2025-1390 → Python buffer overflow → apt-get install libpython3.8=3.8.18-2+deb12u3</li>

                <li>CVE-2025-24528, CVE-2024-26462 → zlib vulnerabilities → apt-get install zlib1g=1:1.2.13.dfsg-1+deb12u3</li>

                <li>CVE-2025-32988 → OpenSSL heap overflow → apt-get install libssl1.1=1.1.1n-0+deb12u3</li>
                </ul>

                <h4>Dockerfile snippet   </h4>
                RUN apt-get update && \ apt-get install -y --no-install-recommends \ libssl1.1=1.1.1n-0+deb12u3 \ zlib1g=1:1.2.13.dfsg-1+deb12u3 && \ rm -rf /var/lib/apt/lists/* 
            """

            if ai_engine == "gemini":
                if not GEMINI_API_KEY:
                    raise RuntimeError("Set GEMINI_API_KEY before using Gemini engine.")
                client = genai.Client(api_key=GEMINI_API_KEY)
                response = client.models.generate_content(
                    model=model,
                    contents=prompt
                )
                ai_text = response.text

            elif ai_engine == "openai":
                if not OPENAI_API_KEY:
                    raise RuntimeError("Set OPENAI_API_KEY before using OpenAI engine.")
                openai.api_key = OPENAI_API_KEY
                response = openai.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are a helpful security and DevSecOps assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0
                )
                ai_text = response.choices[0].message.content  # ✅ Correct access for HTML

            else:
                raise HTTPException(status_code=400, detail="Invalid ai_engine. Use 'gemini' or 'openai'.")

            
            if ai_text.startswith("```html") and ai_text.endswith("```"):
                ai_text = ai_text[len("```html"): -3].strip()

            # Save Data to the DB
            update_ai_recommendation(jenkins_build_number,ai_text)

            email_html = ""
            email_html += "<h2>📊 Vulnerability Fix - AI Recommendations </h2>"
            email_html += "<h3>Project Details:<br> Project: "+project_name+" <br>Image Name - "+str(image_name)+" <br> Ref Build id - "+str(jenkins_build_number)+" <br/> Jenkins Build Details: <a href='"+ci_url+"' >"+ci_url+"</a> </h3> <hr>"
            email_html += "<h3>AI Recommendation</h3><div style='font-size:16px;line-height:21px;'><p>The below is the AI recommendations based on the following CVE issues reported on this build</p><p style='font-size:17px;line-height:23px;color:green;'>"+cve_name+"</p>"
            email_html += ai_text
            email_html += "</div>"
            email_html += "<p style='color:red;font-style:italic;font-size:16px'>Note: This is AI Generated suggestion, this might be wrong as well. So Kindly Check the CVE Documentation for fixes and resolve the issue.</p>"

            subject = f"🧠 Smart AI Alert: Vulnerability Fixes for {project_name} Build #{tag}"
            send_email(subject,email_html)

            cur.close()
            conn.close()

            return {
                    "jenkins_build_number": request.jenkins_build_number,
                    "ai_engine": request.ai_engine,
                    "html_content": ai_text}
        else:
            return {
                    "jenkins_build_number": request.jenkins_build_number,
                    "ai_engine": request.ai_engine,
                    "html_content": "No vulnerabilities found 🎉"}

    except Exception as e:
        print(f"Error fetching Data: {e}")
        raise HTTPException(status_code=500, detail="Error fetching API details")

#----- Get the Count of CVE for AI suggestion ---
def check_vulnerability_count(jenkins_build_number):
    """
    Returns the count of unique vulnerabilities for the given build_id.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # First verify the build exists
    build_check_query = """
        SELECT jenkins_build_number AS id 
        FROM build_reports 
		WHERE jenkins_build_number = %s
    """
    cur.execute(build_check_query, (jenkins_build_number,))
    build_exists = cur.fetchone()
    
    if not build_exists:
        print(f"Build ID {jenkins_build_number} not found in build_reports table")
        cur.close()
        conn.close()
        return 0

    # Count vulnerabilities for this build (excluding exceptions)
    query = """
        SELECT COUNT(DISTINCT A.vuln_id) AS vuln_count
		FROM trivy_results AS A
		JOIN build_reports AS B
		  ON A.build_id = B.id
		WHERE B.jenkins_build_number = %s
		  AND A.is_exception = 0
    """
    
    cur.execute(query, (jenkins_build_number,))
    result = cur.fetchone()
    vuln_count = result[0] if result else 0

    cur.close()
    conn.close()
    
    print(f"Found {vuln_count} vulnerabilities for Jenkins Build {jenkins_build_number}")
    return vuln_count

#----- Get the List of CVE for AI suggestion ---
def get_vuln_ids(jenkins_build_number):
    """
    Returns a comma-separated string of unique vuln_id for the given build_id.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # First verify the build exists
    build_check_query = """
        SELECT jenkins_build_number AS id 
		FROM build_reports 
        WHERE jenkins_build_number  = %s
    """
    cur.execute(build_check_query, (jenkins_build_number,))
    build_exists = cur.fetchone()
    
    if not build_exists:
        print(f"Build ID {jenkins_build_number} not found in build_reports table")
        cur.close()
        conn.close()
        return ""

    query = """
        SELECT A.vuln_id vuln_id
		FROM trivy_results AS A
		JOIN build_reports AS B
		  ON A.build_id = B.id
		WHERE B.jenkins_build_number = %s
		  AND A.is_exception = 0
    """
    
    cur.execute(query, (jenkins_build_number,))
    rows = cur.fetchall()

    # Extract unique vuln_ids and sort
    unique_vulns_set = {row['vuln_id'] for row in rows if row['vuln_id']}
    vuln_ids_str = ",".join(sorted(unique_vulns_set))

    cur.close()
    conn.close()
    
    print(f"Found CVEs for Jenkins Build {jenkins_build_number}: {vuln_ids_str[:100]}...")
    return vuln_ids_str

#--- Save AI Recommendation to DB----
def update_ai_recommendation(jenkins_build_number, html_content):
    # Parse HTML
    soup = BeautifulSoup(html_content, "html.parser")
    clean_text = soup.get_text(separator="\n", strip=True)

    # Extract text from <li> with proper newlines
    # lines = [li.get_text(strip=True) for li in soup.find_all("li")]
    # clean_text = "\n".join(lines)

    conn = get_db_connection()
    cur = conn.cursor()
    update_query = """
        UPDATE build_reports
        SET 
            ai_recommendation = %s, 
            ai_recommendation_html = %s

        WHERE jenkins_build_number = %s
    """
    cur.execute(update_query, (clean_text, html_content,jenkins_build_number))
    conn.commit()
    cur.close()
    conn.close()
