# CyberPulse Compliance (n8n Community Node)

Custom n8n node that evaluates compliance controls against major frameworks (ISO 27001, NIST CSF, PCI DSS, Essential Eight, GDPR, etc.).

---

## ✨ Features
- Classifies control text into categories: MFA, Encryption, Logging, Backups, Patching, Access Reviews.  
- Validates evidence links.  
- Returns compliance status: **Compliant / Partial / Non-Compliant**.  
- Maps controls to frameworks via external `crosswalk.json`.

---

## 🚀 Installation
1. In n8n, go to **Settings → Community Nodes → Install**.  
2. Enter:
   ```bash
   n8n-nodes-cyberpulse-compliance
🔧 Usage

Example workflow:

Add CyberPulse Compliance Node in your workflow.

Provide compliance control text or questionnaire input.

The node validates and classifies the response.

Outputs can be routed to Google Sheets, Email, or Dashboards.

Example Input:
PCI DSS Control 1.2 – Is a firewall deployed?

Example Output:
Compliant | Partial | Non-Compliant (with notes and framework mapping).

📦 Links

npm package

GitHub repository

📜 License

MIT License – see LICENSE
 for details.

 ## 📦 Links
 
-	This project is licensed under the [MIT License](./LICENSE).
- [npm package](https://www.npmjs.com/package/n8n-nodes-cyberpulse-compliance)  
- [GitHub repository](https://github.com/gitadta/n8n-nodes-cyberpulse-compliance)

