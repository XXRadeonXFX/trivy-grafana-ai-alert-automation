#!/usr/bin/env python3
import os, sys, json, psycopg2
from datetime import datetime
import requests

if len(sys.argv) < 10:  # minimum required arguments
    print("Usage: report.py <json_path> <image> <tag> <project_name> <ci_url> <CVE_DB_HOST> <CVE_DB_USERNAME> <CVE_DB_PASSWORD> <CVE_DB_NAME>", file=sys.stderr)
    sys.exit(1)

json_path = sys.argv[1]
image = sys.argv[2]
tag = sys.argv[3]
project_name = sys.argv[4]
ci_url = sys.argv[5]
CVE_DB_HOST = sys.argv[6]
CVE_DB_USERNAME = sys.argv[7]
CVE_DB_PASSWORD = sys.argv[8]
CVE_DB_NAME = sys.argv[9]

if not json_path or not os.path.exists(json_path):
    print(f"Report not found: {json_path}", file=sys.stderr)
    sys.exit(2)

with open(json_path) as f:
    data = json.load(f)

# ------------------ Load Exceptions ------------------
base_dir = os.path.dirname(__file__)  # path where report.py is located
exceptions_file = os.path.join(base_dir, "exceptions.txt")
with open(exceptions_file) as f:
    exceptions = set(line.strip() for line in f if line.strip())

# ------------------ Process Vulnerabilities ------------------
counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "EXCEPTION": 0}
vulns = []
vuln_array = set()  # Use a set for uniqueness

for r in data.get("Results", []):
    # Vulnerabilities
    for v in r.get("Vulnerabilities", []) or []:
        sev = v.get("Severity", "UNKNOWN").upper()
        vuln_id = v.get("VulnerabilityID")
        if vuln_id not in exceptions:
            counts[sev] = counts.get(sev, 0) + 1
        else:
            counts["EXCEPTION"] = counts.get("EXCEPTION", 0) + 1
            
        # Check exception status
        is_exception = 1 if vuln_id in exceptions else 0

        vulns.append({
            "vuln_id": vuln_id,
            "severity": sev,
            "pkg_name": v.get("PkgName"),
            "installed": v.get("InstalledVersion"),
            "fixed": v.get("FixedVersion"),
            "status": v.get("Status"),
            "primary_url": v.get("PrimaryURL"),
            "vendor_severity": v.get("VendorSeverity"),
            "is_exception": is_exception
        })

        if vuln_id:
            vuln_array.add(vuln_id)

# Secrets
secrets = []
for r in data.get("Results", []):
    if r.get("Class") == "secret":
        target = r.get("Target")
        for s in r.get("Secrets", []):
            sev = s.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0)  # Include secret severity in summary

            secrets.append({
                "target": target,
                "rule_id": s.get("RuleID"),
                "category": s.get("Category"),
                "severity": sev,
                "title": s.get("Title"),
                "start_line": s.get("StartLine"),  # Add start_line
                "end_line": s.get("EndLine"),      # Add end_line
                "match_line": s.get("Match"),
                "code": s.get("Code"),             # Keep as JSON or None
                "layer": s.get("Layer")            # Keep as JSON or None
            })


# ------------------ Save to Postgres ------------------

build_id = None  # Ensure variable exists even if DB insert fails

try:
    summary = ""
    # Trivy Report DB Connection
    conn = psycopg2.connect(
        dbname=CVE_DB_NAME,
        user=CVE_DB_USERNAME,
        password=CVE_DB_PASSWORD,
        host=CVE_DB_HOST,
        port="5432"
    )
    cur = conn.cursor()

    # Create tables if not exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS build_reports (
            id SERIAL PRIMARY KEY,
            project TEXT,
            image TEXT,
            tag TEXT,
            ci_url TEXT,
            full_report JSONB,
            timestamp TIMESTAMP,
            ai_recommendation TEXT DEFAULT NULL,
            ai_recommendation_html TEXT DEFAULT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS trivy_results (
            id SERIAL PRIMARY KEY,
            build_id INT REFERENCES build_reports(id),
            severity TEXT,
            vuln_id TEXT,
            pkg_name TEXT,
            installed TEXT,
            fixed TEXT,
            status TEXT,
            primary_url TEXT,
            vendor_severity JSONB,
            timestamp TIMESTAMP,
            is_exception INT DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS trivy_secrets (
            id SERIAL PRIMARY KEY,
            build_id INT REFERENCES build_reports(id),
            target TEXT,
            rule_id TEXT,
            category TEXT,
            severity TEXT,
            title TEXT,
            start_line INT,
            end_line INT,
            match TEXT,
            code JSONB,
            layer JSONB,
            timestamp TIMESTAMP
        )
    """)

    # Insert full JSON report
    cur.execute("""
        INSERT INTO build_reports (project, image, tag, ci_url, full_report, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (project_name, image, tag, ci_url, json.dumps(data), datetime.utcnow()))
    build_id = cur.fetchone()[0]

    # Insert vulnerabilities
    for v in vulns:
        cur.execute("""
            INSERT INTO trivy_results (build_id, severity, vuln_id, pkg_name, installed, fixed,
                                       status, primary_url, vendor_severity, timestamp, is_exception)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (build_id, v["severity"], v["vuln_id"], v["pkg_name"], v["installed"], v["fixed"],
              v["status"], v["primary_url"], json.dumps(v["vendor_severity"]), datetime.utcnow(), v["is_exception"]))

    # Insert secrets
    for s in secrets:
        cur.execute("""
            INSERT INTO trivy_secrets (build_id, target, rule_id, category, severity, title,
                                    start_line, end_line, match, code, layer, timestamp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            build_id,
            s.get("target"),
            s.get("rule_id"),
            s.get("category"),
            s.get("severity"),
            s.get("title"),
            s.get("start_line"),
            s.get("end_line"),
            s.get("match_line"),
            json.dumps(s.get("code")) if s.get("code") else None,
            json.dumps(s.get("layer")) if s.get("layer") else None,
            datetime.utcnow()
        ))


    # 🔎 Fetch unique vuln_id + severity for this build
    cur.execute("""
        SELECT DISTINCT vuln_id, severity
        FROM trivy_results
        WHERE build_id = %s
        ORDER BY severity DESC, vuln_id ASC
    """, (build_id,))
    vuln_rows = cur.fetchall()

    if vuln_rows:
        summary += """
        <h3>Top Vulnerabilities (this run)</h3>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
          <tr>
            <th>Vulnerability ID</th>
            <th>Severity</th>
          </tr>
        """
        for vuln_id, severity in vuln_rows:
            if vuln_id.startswith("CVE-"):
                link = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
            else:
                # fallback: search on Google or OS-specific advisory
                link = f"https://google.com/search?q={vuln_id}"
            summary += f"""
              <tr>
                <td><a href="{link}">{vuln_id}</a></td>
                <td>{severity}</td>
              </tr>
            """
        summary += "</table>"

   

    conn.commit()
    cur.close()
    conn.close()

except Exception as e:
    print(f"Database insert failed: {e}", file=sys.stderr)

# ------------------ Print Summary ------------------
print_summary = (
    f"Project: {project_name}\n"
    f"Image: {image}:{tag}\n"
    f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
    f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | UNKNOWN: {counts['UNKNOWN']} | build_id: {build_id} \n"
)

print(print_summary)