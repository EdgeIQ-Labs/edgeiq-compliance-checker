# EdgeIQ Compliance Checker

Maps SOC2 security controls to EdgeIQ scan findings to produce an automated compliance readiness assessment.

## What It Does

- Reads scan data from EdgeIQ's existing sample-data directory (XSS, Network, SSL scans)
- Evaluates 8 SOC2 controls against findings to produce a pass/fail/warning status per control
- Computes an overall compliance score (0–100) and letter grade (A–F)
- Serves a dashboard UI and a JSON API endpoint

## Controls Evaluated

| Control | Name | Findings Mapped |
|---------|------|-----------------|
| CC6.1 | Logical and Physical Access Controls | SSL issues + open ports |
| CC6.2 | Logical Access Controls | XSS findings |
| CC6.6 | Security for Remote Computing | Exposed admin/DB ports |
| CC7.2 | Vulnerability Management | CVE findings |
| CC8.1 | Change Management | Subdomain enumeration (stubbed) |
| A1 | Injection | SQL injection + XSS |
| A3 | Data Integrity | SSL certificate integrity |
| A5 | Logging and Monitoring | Scan coverage completeness |

## API

```
GET /api/compliance?domain=example.com&framework=soc2
```

Returns:
```json
{
  "domain": "example.com",
  "framework": "SOC2",
  "score": 62.5,
  "grade": "C",
  "total_controls": 8,
  "passed": 3,
  "warning": 2,
  "failed": 3,
  "controls": [
    {
      "id": "CC6.1",
      "name": "Logical and Physical Access Controls",
      "category": "Security",
      "status": "fail",
      "score": 0,
      "finding_count": 5,
      "action": "Fix critical SSL issues..."
    }
  ],
  "findings_summary": {
    "total": 14,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 2,
    "info": 1
  }
}
```

## Score Formula

```
score = 100 - (failed_controls × 12.5)
```

- **Grade A:** 90–100
- **Grade B:** 70–89
- **Grade C:** 50–69
- **Grade D:** 30–49
- **Grade F:** 0–29

## Usage

```bash
cd edgeiq-compliance-checker/src
pip install -r ../requirements.txt
python server.py
# → listens on 0.0.0.0:8114 (PORT env var supported)
```

Dashboard: `http://localhost:8114/`

## Pricing (shown in UI)

- **Essential:** $49/mo — SOC2, HIPAA ready
- **Business:** $99/mo — All frameworks + more

## Files

```
edgeiq-compliance-checker/
├── SKILL.md
├── README.md
├── requirements.txt
├── src/server.py        # Flask app + API
├── templates/index.html # Dashboard UI
└── data/controls.json   # SOC2 control definitions
```

## Deploy

Render.com-compatible. Set `PORT` env var (default 8114). No database required.
