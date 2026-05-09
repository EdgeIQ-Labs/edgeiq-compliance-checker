#!/usr/bin/env python3
"""
EdgeIQ Compliance Checker — SOC2 controls mapped to EdgeIQ scan findings.
Serves the compliance dashboard UI and exposes the /api/compliance endpoint.
"""
import json
import os
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from werkzeug.serving import run_simple

# ── config ──────────────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8114"))
BASE_DIR = Path(__file__).resolve().parents[1]
SAMPLE_DIR = BASE_DIR.parent / "edgeiq-smb-security-dashboard" / "sample-data"
CONTROLS_FILE = BASE_DIR / "data" / "controls.json"
UPGRADE_URL = os.getenv("UPGRADE_URL", "https://buy.stripe.com/3cI28tcuf6d76w42cg7wA20")

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

# ── helpers ──────────────────────────────────────────────────────────────────────

def _load_json(domain, prefix):
    """Load <prefix>_<domain>.json from the shared sample-data dir."""
    p = SAMPLE_DIR / f"{prefix}_{domain}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def _grade(score):
    if score >= 90: return "A"
    if score >= 70: return "B"
    if score >= 50: return "C"
    if score >= 30: return "D"
    return "F"


def _status_from_score(control_score):
    """Convert per-control 0-1 pass ratio to pass/fail/warning."""
    if control_score >= 0.8: return "pass"
    if control_score >= 0.4: return "warning"
    return "fail"


def _severity_weight(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


# ── scan data → findings ───────────────────────────────────────────────────────

def _collect_findings(domain):
    """Aggregate all findings across scan types for a domain."""
    findings = []

    xss = _load_json(domain, "xss")
    for f in xss.get("findings", []):
        findings.append({
            "source": "xss_scanner",
            "type": "xss",
            "severity": f.get("severity", "info").lower(),
            "title": f.get("vulnerability", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "description": f.get("description", ""),
        })

    net = _load_json(domain, "network")
    for p in net.get("open_ports", []):
        findings.append({
            "source": "network_scanner",
            "type": "port",
            "severity": p.get("severity", "info").lower(),
            "title": f"Open port {p['port']} ({p.get('service', '')})",
            "port": p.get("port", ""),
            "service": p.get("service", ""),
            "description": p.get("risk", ""),
        })
    for c in net.get("cves", []):
        findings.append({
            "source": "network_scanner",
            "type": "cve",
            "severity": c.get("severity", "info").lower(),
            "title": c.get("cve_id", ""),
            "cvss": c.get("cvss", 0.0),
            "description": c.get("description", ""),
            "remediation": c.get("remediation", ""),
        })

    ssl = _load_json(domain, "ssl")
    for iss in ssl.get("issues", []):
        findings.append({
            "source": "ssl_watcher",
            "type": "ssl",
            "severity": iss.get("severity", "info").lower(),
            "title": iss.get("title", ""),
            "description": iss.get("description", ""),
            "remediation": iss.get("remediation", ""),
        })
    # SSL certificate chain integrity
    days_exp = ssl.get("days_until_expiry", 999)
    if days_exp < 0:
        findings.append({
            "source": "ssl_watcher",
            "type": "ssl",
            "severity": "critical",
            "title": "SSL Certificate Expired",
            "description": f"Certificate expired {-days_exp} days ago.",
        })
    if ssl.get("certificate_chain"):
        chain = ssl["certificate_chain"]
        if len(chain) < 2:
            findings.append({
                "source": "ssl_watcher",
                "type": "ssl",
                "severity": "medium",
                "title": "Incomplete Certificate Chain",
                "description": "Certificate chain is incomplete or missing intermediate cert.",
            })

    return findings


# ── evaluate controls ─────────────────────────────────────────────────────────

def _evaluate_cc61(domain, findings):
    """CC6.1 — boundary protection: SSL issues + open ports."""
    ssl_issues = [f for f in findings if f["type"] == "ssl"]
    ports = [f for f in findings if f["type"] == "port"]
    critical_ports = [p for p in ports if p.get("port") in (22, 3306, 5432, 27017, 6379)]
    score = 1.0
    action = None
    if any(f["severity"] in ("critical", "high") for f in ssl_issues):
        score = 0.0
        action = "Fix critical SSL issues (expired cert, weak cipher, missing chain)."
    elif any(f["severity"] == "medium" for f in ssl_issues):
        score = 0.5
        action = "Address medium-severity SSL warnings."
    if critical_ports:
        score = min(score, 0.3)
        action = f"Critical ports exposed: {[p['port'] for p in critical_ports]}. Restrict access immediately."
    if not action:
        action = "Boundary protection looks solid. Monitor for new exposures."
    return score, action


def _evaluate_cc62(domain, findings):
    """CC6.2 — endpoint protection: XSS findings."""
    xss = [f for f in findings if f["type"] == "xss"]
    if any(f["severity"] == "critical" for f in xss):
        return 0.0, "Critical XSS vulnerabilities found. Sanitize all user inputs and enable WAF."
    if any(f["severity"] == "high" for f in xss):
        return 0.2, "High-severity XSS found. Patch vulnerable parameters immediately."
    if xss:
        return 0.5, f"{len(xss)} XSS finding(s) present. Review and remediate injection points."
    return 1.0, "No XSS findings. Endpoint protection is clean."


def _evaluate_cc66(domain, findings):
    """CC6.6 — security logging: port exposure risk (admin/DB ports open)."""
    ports = [f for f in findings if f["type"] == "port"]
    risky = [p for p in ports if p.get("port") in (22, 3306, 5432, 27017, 6379, 11211)]
    if risky:
        return 0.0, f"Risky ports exposed to internet: {[p['port'] for p in risky]}. Close or restrict access."
    if any(p["severity"] in ("high", "critical") for p in ports):
        return 0.4, "High-risk ports open. Apply firewall rules to restrict exposure."
    return 1.0, "No risky remote access ports detected. Logging boundary is protected."


def _evaluate_cc72(domain, findings):
    """CC7.2 — vulnerability management: CVE findings."""
    cves = [f for f in findings if f["type"] == "cve"]
    if any(f["severity"] == "critical" for f in cves):
        return 0.0, f"Critical CVE(s) present: {[c['title'] for c in cves if c['severity']=='critical']}. Patch immediately."
    if any(f["severity"] == "high" for f in cves):
        return 0.3, f"High-severity CVE(s) found. Prioritize patching: {[c['title'] for c in cves if c['severity']=='high'][:3]}"
    if cves:
        return 0.6, f"{len(cves)} CVE(s) found. Schedule remediation per CVSS score."
    return 1.0, "No known critical vulnerabilities detected."


def _evaluate_cc81(domain, findings):
    """CC8.1 — change management: subdomain enumeration (stubbed via scan coverage)."""
    # In a real product this would come from a subdomain enum scan.
    # We warn if scan coverage looks thin.
    net = _load_json(domain, "network")
    subdomains = net.get("subdomains", [])
    if not subdomains:
        return 0.7, "Subdomain enumeration not run. Consider adding DNS/shadow asset discovery to your scan pipeline."
    return 1.0, f"Found {len(subdomains)} subdomains. Review for unintended exposures."


def _evaluate_a1(domain, findings):
    """A1 — injection: SQL injection / XSS."""
    xss = [f for f in findings if f["type"] == "xss"]
    sql = [f for f in findings if f["type"] == "sql_injection"]
    combined = xss + sql
    if any(f["severity"] == "critical" for f in combined):
        return 0.0, "Critical injection vulnerability. Implement parameterized queries and input validation now."
    if any(f["severity"] == "high" for f in combined):
        return 0.25, "High-severity injection found. Sanitize inputs and apply WAF rules."
    if combined:
        return 0.5, f"{len(combined)} injection finding(s). Review ORM usage and query construction."
    return 1.0, "No injection vulnerabilities detected."


def _evaluate_a3(domain, findings):
    """A3 — data integrity: SSL certificate integrity."""
    ssl_findings = [f for f in findings if f["type"] == "ssl"]
    expired = [f for f in ssl_findings if "expired" in f.get("title", "").lower()]
    incomplete = [f for f in ssl_findings if "incomplete" in f.get("title", "").lower()]
    if expired:
        return 0.0, "SSL certificate is expired. Renew immediately to protect data-in-transit integrity."
    if incomplete:
        return 0.4, "Certificate chain is incomplete. Fix chain to ensure client-side trust validation."
    critical_ssl = [f for f in ssl_findings if f["severity"] in ("critical", "high")]
    if critical_ssl:
        return 0.3, f"SSL integrity issues: {[f['title'] for f in critical_ssl]}"
    return 1.0, "SSL certificate is valid, chain is intact, and TLS configuration is sound."


def _evaluate_a5(domain, findings):
    """A5 — logging: scan coverage completeness."""
    xss = _load_json(domain, "xss")
    net = _load_json(domain, "network")
    ssl = _load_json(domain, "ssl")
    scans = {"xss": xss, "network": net, "ssl": ssl}
    missing = [k for k, v in scans.items() if not v]
    coverage = max(0, (3 - len(missing)) / 3)
    if len(missing) >= 2:
        return 0.3, f"Multiple scan types missing ({missing}). Your logging/visibility is incomplete. Add missing scanners."
    if missing:
        return 0.7, f"Scan type {missing[0]} not available. Add it for full coverage."
    return 1.0, f"All scan types present. Coverage is complete ({int(coverage*100)}%)."


EVALUATORS = {
    "CC6.1": _evaluate_cc61,
    "CC6.2": _evaluate_cc62,
    "CC6.6": _evaluate_cc66,
    "CC7.2": _evaluate_cc72,
    "CC8.1": _evaluate_cc81,
    "A1":    _evaluate_a1,
    "A3":   _evaluate_a3,
    "A5":   _evaluate_a5,
}


# ── scoring ──────────────────────────────────────────────────────────────────────

def _compute_compliance_score(domain, controls):
    """Compute overall compliance score: 100 - (failed_controls * 12.5)."""
    findings = _collect_findings(domain)
    results = []

    for ctrl in controls:
        evaluator = EVALUATORS.get(ctrl["id"])
        if evaluator:
            score, action = evaluator(domain, findings)
        else:
            score, action = 1.0, "No scan data available for this control."

        severity = findings[0].get("severity", "info") if findings else "info"
        finding_count = len([f for f in findings if _severity_weight(f.get("severity","info")) >= _severity_weight(severity)])

        status = _status_from_score(score)
        results.append({
            "id": ctrl["id"],
            "name": ctrl["name"],
            "category": ctrl["category"],
            "status": status,
            "score": round(score * 100),
            "finding_count": len([f for f in findings if f["type"] in _ctrl_finding_types(ctrl)]),
            "action": action,
        })

    failed = sum(1 for r in results if r["status"] == "fail")
    score = max(0, 100 - (failed * 12.5))
    grade = _grade(score)
    return score, grade, results


def _ctrl_finding_types(ctrl):
    mapping = {
        "CC6.1": ["ssl", "port"],
        "CC6.2": ["xss"],
        "CC6.6": ["port"],
        "CC7.2": ["cve"],
        "CC8.1": [],
        "A1":    ["xss", "sql_injection"],
        "A3":   ["ssl"],
        "A5":   [],
    }
    return mapping.get(ctrl["id"], [])


# ── routes ──────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "edgeiq-compliance-checker"})


@app.route("/api/compliance")
def api_compliance():
    domain = request.args.get("domain", "example.com").strip().lower()
    framework = request.args.get("framework", "soc2").strip().lower()

    # Load controls
    try:
        controls = json.loads(CONTROLS_FILE.read_text())["controls"]
    except Exception:
        return jsonify({"error": "failed_to_load_controls", "message": "Could not load controls data."}), 500

    # Filter by framework stub
    if framework == "soc2":
        controls = [c for c in controls]  # all controls for now
    else:
        controls = [c for c in controls]  # stub: serve all; expand later

    findings = _collect_findings(domain)
    score, grade, results = _compute_compliance_score(domain, controls)
    failed = sum(1 for r in results if r["status"] == "fail")
    warning = sum(1 for r in results if r["status"] == "warning")
    passed = sum(1 for r in results if r["status"] == "pass")

    return jsonify({
        "domain": domain,
        "framework": framework.upper(),
        "score": round(score, 1),
        "grade": grade,
        "total_controls": len(controls),
        "passed": passed,
        "warning": warning,
        "failed": failed,
        "controls": results,
        "findings_summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high":     len([f for f in findings if f["severity"] == "high"]),
            "medium":   len([f for f in findings if f["severity"] == "medium"]),
            "low":      len([f for f in findings if f["severity"] == "low"]),
            "info":     len([f for f in findings if f["severity"] == "info"]),
        },
    })


@app.route("/")
def index():
    return render_template("index.html",
        upgrade_url=UPGRADE_URL,
        port=PORT,
    )


# ── bootstrap ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_simple("0.0.0.0", PORT, app, threaded=True, use_reloader=False)
