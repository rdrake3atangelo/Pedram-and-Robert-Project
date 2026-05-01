# Playbook PB2 — Unsanctioned Cloud Storage Access

**Detection Rule:** UC2 — Unsanctioned Cloud Storage Access (`uc2_unsanctioned.spl`)  
**Version:** 1.0 | **Author:** Detection Engineering Project  
**Severity Levels Covered:** Low / Medium / High / Critical

---

## Overview

This playbook guides a SOC analyst when UC2 fires an alert for traffic directed to a domain listed in `unsanctioned_domains.csv`. Unsanctioned cloud storage or file-sharing services are a common vector for both deliberate insider exfiltration and accidental data leakage by employees using consumer tools for business purposes.

**Alert trigger summary:** Outbound traffic was observed from an internal host to a domain on the unsanctioned domain list, and the user or domain does not appear in the `sanctioned_services.csv` exception list.

---

## Step 1 — Initial Validation

**Goal:** Confirm the alert is actionable and not a known exception.

1. **Review the alert fields:** `src_ip`, `hostname`, `user`, `domain`, `flagged_domain`, `total_bytes_gb`, `event_count`.
2. **Check the sanctioned services list** for any approved exception for this user-domain combination:
   ```spl
   | inputlookup sanctioned_services.csv | search domain=<domain> approved_for=<department>
   ```
3. **Verify the domain is correctly flagged:**
   - Confirm the domain in the alert matches an entry in `unsanctioned_domains.csv` (not a subdomain mismatch).
   - Check if a similar-looking sanctioned domain exists (e.g., `sharepoint.com` vs. `sharepoint.io`).
4. **Review the volume:**
   - Small volume (< 10 MB, 1–2 events): May be accidental or browser-cached redirect. Lower priority.
   - Large volume (> 100 MB or multiple events): Strong exfiltration signal. Increase severity.

**Decision point:**
- Valid exception found in `sanctioned_services.csv` → Document and close. Review whether the exception CSV needs updating.
- No valid exception → Continue to Step 2.

---

## Step 2 — Enrichment

**Goal:** Build a complete picture of the activity and the user's intent.

1. **Identify the user and their role:**
   ```spl
   | inputlookup asset_inventory.csv | search src_ip=<src_ip>
   ```
2. **Assess whether cloud storage is needed for this role:**
   - Engineering / DevOps: May have legitimate need for external repos; verify with manager.
   - Finance / HR / Legal: High-risk departments — cloud storage should not be necessary; treat as elevated risk.
3. **Review the user's prior alert history:**
   ```spl
   index=notable user=<user> earliest=-90d
   | stats count by alert_name severity
   | sort - count
   ```
4. **Correlate with DLP policy logs:**
   ```spl
   index=dlp_policy user=<user> earliest=-24h
   | table _time policy_name action severity
   ```
5. **Determine the mechanism of upload:**
   - Browser-based upload (single large POST request): Likely manual exfiltration.
   - Multiple small requests (sync client pattern): Likely a sync client installed on the endpoint.
   - API-style requests: Higher sophistication; consider external attacker scenario.
6. **Check endpoint for installed cloud sync clients** (if EDR available): Dropbox, MEGASync, rclone, etc.
7. **Review HR status** of the user for insider-threat risk factors.

---

## Step 3 — Containment and Remediation

**Goal:** Prevent further data from leaving the organisation and address the root cause.

### Immediate containment:

1. **Block the unsanctioned domain at the web proxy:**
   - If not already blocked (verify why the domain was accessible), submit an emergency block request.
   - Most domains in `unsanctioned_domains.csv` should already be blocked in the proxy deny list; if not, this is a gap to remediate.

2. **Initiate a user interview** through the HR/security team:
   - Inform the user's manager that a security review is being conducted.
   - Do not alert the user directly until the security and HR teams are aligned.

3. **Scan the endpoint for cloud sync clients:**
   - Remove any unauthorized cloud sync software.
   - Revoke any OAuth tokens granted to cloud storage apps.

4. **Request a data recovery assessment:**
   - For services like Dropbox or OneDrive for Business with admin access, attempt to identify what files were shared.
   - For services without recovery capability (mega.nz, transfer.sh), document that recovery is not possible.

### If malicious intent is confirmed:

- Suspend the user's account pending HR review.
- Preserve all evidence (logs, endpoint artifacts) with a legal hold.
- Proceed to Step 4 escalation.

---

## Step 4 — Escalation, Communication, and Documentation

### Escalation matrix:

| Condition | Escalate To | SLA |
|---|---|---|
| Accidental / first offense, small volume | Manager + SOC Tier 2 | 8 hours |
| Repeated violations or large volume | CISO + HR | 2 hours |
| Sensitive data (PII/IP/financial) confirmed | CISO + Legal + HR | 1 hour |
| Account compromise suspected | CISO + Incident Response | Immediately |
| C-suite user involved | CISO + Board as appropriate | Immediately |

### Documentation requirements:

- Open an incident ticket recording: alert ID, detection rule, user, domain, bytes transferred, event count, enrichment findings, and all actions taken.
- Record whether the event was a deliberate exfiltration, accidental misuse, or false positive.
- If adding to `sanctioned_services.csv` as an approved exception, document the business justification and approver name in the CSV.
- If a proxy block was missing for the domain, file a remediation ticket to update the proxy policy.
