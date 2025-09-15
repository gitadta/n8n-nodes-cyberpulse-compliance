# CyberPulse Compliance (n8n Community Node)

Custom n8n node that evaluates compliance controls against major frameworks (ISO 27001, NIST CSF, PCI DSS, Essential Eight, GDPR).

## Features
- Classifies control text into categories: MFA, Encryption, Logging, Backups, Patching, Access Reviews.
- Validates evidence links.
- Returns compliance status: Compliant / Partial / Non-Compliant.
- Maps controls to frameworks via external `crosswalk.json`.

## Installation
1. In n8n, go to **Settings → Community Nodes → Install**.
2. Enter:


