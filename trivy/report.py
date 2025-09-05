#!/usr/bin/env python3
import os, sys, json, psycopg2
from datetime import datetime
import requests
import traceback

# Add debug flag
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'

def debug_print(message):
    if DEBUG:
        print(f"DEBUG: {message}", file=sys.stderr)

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

debug_print(f"Arguments received: json_path={json_path}, image={image}, tag={tag}")
debug_print(f"Database params: host={CVE_DB_HOST}, db={CVE_DB_NAME}, user={CVE_DB_USERNAME}")

if not json_path or not os.path.exists(json_path):
    print(f"Report not found: {json_path}", file=sys.stderr)
    sys.exit(2)

try:
    with open(json_path) as f:
        data = json.load(f)
    debug_print(f"Successfully loaded JSON file with {len(data.get('Results', []))} results")
except Exception as e:
    print(f"Failed to load JSON file: {e}", file=sys.stderr)
    sys.exit(2)

# ------------------ Load Exceptions ------------------
base_dir = os.path.dirname(__file__)  # path where report.py is located
exceptions_file = os.path.join(base_dir, "exceptions.txt")
exceptions = set()

try:
    if os.path.exists(exceptions_file):
        with open(exceptions_file) as f:
            exceptions = set(line.strip() for line in f if line.strip())
        debug_print(f"Loaded {len(exceptions)} exceptions from {exceptions_file}")
    else:
        debug_print(f"Exceptions file not found: {exceptions_file}")
except Exception as e:
    debug_print(f"Failed to load exceptions: {e}")

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

debug_print(f"Processed {len(vulns)} vulnerabilities")

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

debug_print(f"Processed {len(secrets)} secrets")

# ------------------ Save to Postgres ------------------

build_id = None  # Ensure variable exists even if DB insert fails

try:
    summary = ""
    debug_print(f"Attempting database connection to {CVE_DB_HOST}:5432/{CVE_DB_NAME}")
    
    # Test database connection with better error handling
    try:
        conn = psycopg2.connect(
            dbname=CVE_DB_NAME,
            user=CVE_DB_USERNAME,
            password=CVE_DB_PASSWORD,
            host=CVE_DB_HOST,
            port="5432",
            connect_timeout=10
        )
        debug_print("Database connection successful")
    except psycopg2.OperationalError as e:
        print(f"Database connection failed: {e}", file=sys.stderr)
        print(f"Check if PostgreSQL is running on {CVE_DB_HOST}:5432", file=sys.stderr)
        print(f"Check credentials: user={CVE_DB_USERNAME}, database={CVE_DB_NAME}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Unexpected connection error: {e}", file=sys.stderr)
        raise
    
    cur = conn.cursor()

    # Test basic database functionality
    try:
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        debug_print(f"PostgreSQL version: {version}")
    except Exception as e:
        print(f"Failed to query database version: {e}", file=sys.stderr)
        raise

    # Create tables if not exist with better error handling
    try:
        debug_print("Creating tables if they don't exist...")
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS build_reports (
                id SERIAL PRIMARY KEY,
                project TEXT,
                image TEXT,
                tag TEXT,
                jenkins_build_number INT,             -- new column for Jenkins build #
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
                build_id INT REFERENCES build_reports(id) ON DELETE CASCADE,
                jenkins_build_number INT,             -- store Jenkins build number
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
                build_id INT REFERENCES build_reports(id) ON DELETE CASCADE,
                jenkins_build_number INT,             -- store Jenkins build number
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
        
        debug_print("Tables created/verified successfully")
        
    except Exception as e:
        print(f"Failed to create tables: {e}", file=sys.stderr)
        raise

    # Insert full JSON report
    try:
        debug_print("Inserting build report...")
        
        # Validate JSON data before inserting
        try:
            json_data = json.dumps(data)
            if len(json_data) > 100000000:  # 100MB limit
                print("Warning: JSON report is very large, truncating...", file=sys.stderr)
                json_data = json_data[:100000000]
        except Exception as e:
            print(f"Failed to serialize JSON data: {e}", file=sys.stderr)
            json_data = '{"error": "Failed to serialize scan data"}'
        
        # Extract Jenkins build number from tag
        jenkins_build_number = int(''.join([c for c in tag if c.isdigit()]))
        
        cur.execute("""
            INSERT INTO build_reports (project, image, tag, ci_url, full_report, timestamp, jenkins_build_number)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (project_name, image, tag, ci_url, json_data, datetime.utcnow(), jenkins_build_number))
        
        build_id = cur.fetchone()[0]
        debug_print(f"Build report inserted with ID: {build_id}")
        
    except Exception as e:
        print(f"Failed to insert build report: {e}", file=sys.stderr)
        print(f"Data: project={project_name}, image={image}, tag={tag}", file=sys.stderr)
        raise

    # Insert vulnerabilities with batch processing
    try:
        debug_print(f"Inserting {len(vulns)} vulnerabilities...")
        
        if vulns:
            # Use batch insert for better performance
            vuln_data = []
            for v in vulns:
                vendor_severity_json = json.dumps(v["vendor_severity"]) if v["vendor_severity"] else None
                vuln_data.append((
                    build_id, 
                    v["severity"], 
                    v["vuln_id"], 
                    v["pkg_name"], 
                    v["installed"], 
                    v["fixed"],
                    v["status"], 
                    v["primary_url"], 
                    vendor_severity_json, 
                    datetime.utcnow(), 
                    v["is_exception"]
                ))
            
            # Insert in batches to avoid memory issues
            batch_size = 1000
            for i in range(0, len(vuln_data), batch_size):
                batch = vuln_data[i:i+batch_size]
                cur.executemany("""
                    INSERT INTO trivy_results (build_id, jenkins_build_number, severity, vuln_id, pkg_name, installed, fixed,
                                               status, primary_url, vendor_severity, timestamp, is_exception)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    (build_id, jenkins_build_number, v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])
                    for v in vuln_data
                ])
                debug_print(f"Inserted vulnerability batch {i//batch_size + 1}")
        
        debug_print("Vulnerabilities inserted successfully")
        
    except Exception as e:
        print(f"Failed to insert vulnerabilities: {e}", file=sys.stderr)
        traceback.print_exc()
        # Continue with secrets even if vulnerabilities fail

    # Insert secrets
    try:
        debug_print(f"Inserting {len(secrets)} secrets...")
        
        if secrets:
            for s in secrets:
                try:
                    cur.execute("""
                        INSERT INTO trivy_secrets (build_id, jenkins_build_number, target, rule_id, category, severity, title,
                                                   start_line, end_line, match, code, layer, timestamp)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (
                        build_id,
                        jenkins_build_number,
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
                except Exception as e:
                    debug_print(f"Failed to insert secret {s.get('rule_id', 'unknown')}: {e}")
                    continue
        
        debug_print("Secrets inserted successfully")
        
    except Exception as e:
        print(f"Failed to insert secrets: {e}", file=sys.stderr)
        # Continue even if secrets fail

    # Generate summary
    try:
        debug_print("Generating vulnerability summary...")
        
        # 🔎 Fetch unique vuln_id + severity for this build
        cur.execute("""
            SELECT DISTINCT vuln_id, severity
            FROM trivy_results
            WHERE build_id = %s AND vuln_id IS NOT NULL
            ORDER BY severity DESC, vuln_id ASC
            LIMIT 50
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
                if vuln_id and vuln_id.startswith("CVE-"):
                    link = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
                else:
                    # fallback: search on Google or OS-specific advisory
                    link = f"https://google.com/search?q={vuln_id}" if vuln_id else "#"
                summary += f"""
                  <tr>
                    <td><a href="{link}">{vuln_id or 'Unknown'}</a></td>
                    <td>{severity}</td>
                  </tr>
                """
            summary += "</table>"
        else:
            summary = "<p>No vulnerabilities found in database for this build.</p>"
            
        debug_print("Summary generated successfully")

    except Exception as e:
        print(f"Failed to generate summary: {e}", file=sys.stderr)
        summary = "<p>Failed to generate vulnerability summary</p>"

    # Commit transaction
    try:
        conn.commit()
        debug_print("Database transaction committed successfully")
    except Exception as e:
        print(f"Failed to commit transaction: {e}", file=sys.stderr)
        conn.rollback()
        raise
    
    cur.close()
    conn.close()
    debug_print("Database connection closed")

except psycopg2.OperationalError as e:
    print(f"Database connection error: {e}", file=sys.stderr)
    print("Possible causes:", file=sys.stderr)
    print("1. PostgreSQL service is not running", file=sys.stderr)
    print("2. Incorrect host/port configuration", file=sys.stderr)
    print("3. Network connectivity issues", file=sys.stderr)
    print("4. Firewall blocking connection", file=sys.stderr)
except psycopg2.DatabaseError as e:
    print(f"Database error: {e}", file=sys.stderr)
    print("Possible causes:", file=sys.stderr)
    print("1. Incorrect database name", file=sys.stderr)
    print("2. User doesn't have required permissions", file=sys.stderr)
    print("3. Database doesn't exist", file=sys.stderr)
except psycopg2.Error as e:
    print(f"PostgreSQL error: {e}", file=sys.stderr)
    traceback.print_exc()
except Exception as e:
    print(f"Unexpected error during database operations: {e}", file=sys.stderr)
    traceback.print_exc()

# ------------------ Print Summary ------------------
print_summary = (
    f"Project: {project_name}\n"
    f"Image: {image}:{tag}\n"
    f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
    f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | UNKNOWN: {counts['UNKNOWN']} | "
    f"EXCEPTIONS: {counts['EXCEPTION']} | build_id: {build_id}\n"
)

print(print_summary)

# Print additional debug info if enabled
if DEBUG:
    print(f"DEBUG: Script completed. Build ID: {build_id}", file=sys.stderr)
    print(f"DEBUG: Total vulnerabilities processed: {len(vulns)}", file=sys.stderr)
    print(f"DEBUG: Total secrets processed: {len(secrets)}", file=sys.stderr)
