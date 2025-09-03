#!/usr/bin/env python3
import os
import json
import sys
from datetime import datetime

# ------------------ Load Exceptions ------------------
base_dir = os.path.dirname(__file__)  # path where email_template.py is located
exceptions_file = os.path.join(base_dir, "exceptions.txt")
with open(exceptions_file) as f:
    exceptions = set(line.strip() for line in f if line.strip())

def build_email(counts, vulns, secrets, ci_url):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Header
    html = f"""
    <p style="font-size:16px; line-height:21px;">
        <b>CRITICAL:</b> {counts['CRITICAL']} |
        <b>HIGH:</b> {counts['HIGH']} |
        <b>MEDIUM:</b> {counts['MEDIUM']} |
        <b>LOW:</b> {counts['LOW']} |
        <b>UNKNOWN:</b> {counts['UNKNOWN']}<br>
        <b>Scan Time:</b> {now}<br>
        {f"<b>CI:</b> <a href='{ci_url}'>{ci_url}</a><br>" if ci_url else ""}
    </p>
    """

    # Vulnerabilities table
    if vulns:
        html += """
        <h3>Vulnerabilities</h3>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
        <tr style="background:#f2f2f2;">
            <th>Vulnerability ID</th>
            <th>Severity</th>
            <th>Package</th>
            <th>Installed</th>
            <th>Fixed</th>
        </tr>
        """
        for v in vulns:
            vuln_id = v["vuln_id"]
            link = v.get("primary_url") or f"https://google.com/search?q={vuln_id}"
            if v['is_exception']==0:
                html += f"""
                <tr>
                    <td><a href='{link}'>{vuln_id}</a></td>
                    <td>{v['severity']}</td>
                    <td>{v['pkg_name']}</td>
                    <td>{v['installed']}</td>
                    <td>{v['fixed']}</td>
                </tr>
                """
        html += "</table>"
    else:
        html += "<p><b>No vulnerabilities found 🎉</b></p>"

    # Expection Vulnerabilities table
    if vulns:
        html += """
        <h3>⚠️ Ignored Vulnerabilities (Approved Exceptions)</h3>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
        <tr style="background:#f2f2f2;">
            <th>Vulnerability ID</th>
            <th>Severity</th>
            <th>Package</th>
            <th>Installed</th>
            <th>Fixed</th>
        </tr>
        """
        for v in vulns:
            vuln_id = v["vuln_id"]
            link = v.get("primary_url") or f"https://google.com/search?q={vuln_id}"
            if v['is_exception']==1:
                html += f"""
                <tr>
                    <td><a href='{link}'>{vuln_id}</a></td>
                    <td>{v['severity']}</td>
                    <td>{v['pkg_name']}</td>
                    <td>{v['installed']}</td>
                    <td>{v['fixed']}</td>
                </tr>
                """
        html += "</table>"
    else:
        html += "<p><b>No Ignored Vulnerabilities (Approved Exceptions) found 🎉</b></p>"

    # Secrets table
    if secrets:
        html += """
        <h3>Secrets</h3>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse;">
        <tr style="background:#f2f2f2;">
            <th>Target</th>
            <th>Rule ID</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Match</th>
        </tr>
        """
        for s in secrets:
            html += f"""
            <tr>
                <td>{s['target']}</td>
                <td>{s['rule_id']}</td>
                <td>{s['category']}</td>
                <td>{s['severity']}</td>
                <td>{s['title']}</td>
                <td><pre>{s['match_line']}</pre></td>
            </tr>
            """
        html += "</table>"
    else:
        html += "<p><b>No secrets found 🔐</b></p>"

    return html


if __name__ == "__main__":
    """
    Usage: python3 email_template.py trivy_output.json CI_URL > report.html
    """
    if len(sys.argv) < 2:
        print("Usage: python3 email_template.py trivy_output.json [CI_URL]")
        sys.exit(1)

    trivy_json = sys.argv[1]
    ci_url = sys.argv[2] if len(sys.argv) > 2 else None

    with open(trivy_json, "r") as f:
        data = json.load(f)

    # ------------------ Process Vulnerabilities ------------------
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    vulns = []
    secrets = []

    for r in data.get("Results", []):
        # Vulnerabilities
        for v in r.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            vuln_id = v.get("VulnerabilityID")

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

        # Secrets
        if r.get("Class") == "secret":
            target = r.get("Target")
            for s in r.get("Secrets", []):
                sev = s.get("Severity", "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1
                secrets.append({
                    "target": target,
                    "rule_id": s.get("RuleID"),
                    "category": s.get("Category"),
                    "severity": sev,
                    "title": s.get("Title"),
                    "match_line": s.get("Match")
                })

    html = build_email(counts, vulns, secrets, ci_url)
    print(html)
