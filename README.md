# IDOR Hunter – Behavioral Object Access Analyzer

IDOR Hunter is a Burp Suite extension that detects horizontal Insecure Direct Object Reference (IDOR) vulnerabilities using behavioral response analysis rather than multi-user or authorization header manipulation.

## Key Features
- Intelligent object ID mutation
- Single-session detection
- REST and GraphQL support
- JSON-aware response analysis
- Sensitive data detection
- Severity scoring
- Findings UI with request/response viewer
- Exportable results (JSON)

## Safe by Design
- One mutation per request
- No destructive endpoints tested
- No authentication tampering

## Installation
Burp → Extender → Extensions → Add → Python → idor_hunter.py

## Disclaimer
Use only on systems you are authorized to test.
