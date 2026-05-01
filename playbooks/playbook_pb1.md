# Playbook PB1 — High-Volume Outbound Data Transfer

**Detection Rule:** UC1 — High-Volume Outbound Transfer (`uc1_high_volume.spl`)  
**Version:** 1.0 | **Author:** Detection Engineering Project  
**Severity Levels Covered:** Low / Medium / High / Critical

---

## Overview

This playbook guides a SOC analyst through the triage, investigation, containment, and escalation steps when UC1 fires an alert for an unusually large outbound data transfer from an internal host to an external destination.

**Alert trigger summary:** A single source host transferred more than 500 MB (default threshold) to a single external domain within a one-hour window.

---

## Step 1 — Initial Validation

**Goal:** Confirm the alert is a genuine signal and not a known benign event.

1. **Review the raw alert fields** in Splunk: `src_ip`, `hostname`, `domain`, `total_bytes_gb`, `event_count`, `duration_min`, `user`.
2. **Check the transfer timing:**
   - Does it fall within a known scheduled maintenance or backup window?
   - Run: `index=change_mgmt type=backup OR type=maintenance | search asset=<hostname>` to find authorized windows.
3. **Classify the destination domain:**
   - Is the domain in `sanctioned_services.csv`? → Likely benign; document and close.
   - Is the domain in `unsanctioned_domains.csv`? → Escalate severity; proceed to Step 2.
   - Is the domain unknown? → Proceed to Step 2.
4. **Assess the asset criticality** from `asset_inventory.csv`:
   - Critical asset → immediately escalate to High/Critical severity.
   - Low criticality workstation → continue investigation.

**Decision point:**
- Confirmed benign (scheduled backup to sanctioned destination) → Document and close. Update asset notes if needed.
- Not confirmed benign → Continue to Step 2.

---

## Step 2 — Enrichment

**Goal:** Gather context to support or refute exfiltration hypothesis.

1. **Identify the user associated with the source host:**
   ```spl
   | inputlookup asset_inventory.csv | search src_ip=<src_ip>
   ```
2. **Review recent alert history for the user and host (30 days):**
   ```spl
   index=notable user=<user> OR src_ip=<src_ip> earliest=-30d
   | stats count by alert_name severity
   ```
3. **Check for concurrent unsanctioned domain access (UC2 correlation):**
   ```spl
   index=dlp_test src_ip=<src_ip> earliest=-1h
   | lookup unsanctioned_domains.csv domain OUTPUT flagged_domain
   | where isnotnull(flagged_domain)
   ```
4. **Review endpoint activity for file staging (if EDR available):**
   - Look for large file compressions (`.zip`, `.tar`, `.7z`) in the hour before the transfer.
   - Look for access to sensitive directories (finance shares, HR folders) immediately preceding the transfer.
5. **Assess the destination domain:**
   - Perform a WHOIS lookup on the destination domain.
   - Check VirusTotal or threat intelligence platform for domain reputation.
   - Determine when the domain was registered (newly registered domains are higher risk).
6. **Review the user's HR status:** Has this user submitted a resignation notice, received a performance review, or been placed on a performance improvement plan recently?

**Enrichment summary:** Document all findings in the incident ticket before proceeding.

---

## Step 3 — Containment and Remediation

**Goal:** Stop or limit ongoing exfiltration; preserve evidence.

### If exfiltration is confirmed or strongly suspected:

1. **Block the destination domain at the web proxy/firewall:**
   - Submit a block request to the network team for `<domain>`.
   - Add the domain to the proxy deny list.
   - Verify blocking is effective by confirming no further traffic to the domain from the source host.

2. **Consider host isolation** (escalate to Critical if any of the following apply):
   - The host has access to sensitive data stores.
   - The destination is a newly registered or threat-intelligence-flagged domain.
   - The user's HR status indicates elevated insider-threat risk.
   - Submit a host isolation request to the endpoint team.

3. **Preserve evidence:**
   - Export the raw Splunk events for the alert time window to a secure evidence store.
   - Do not modify or delete logs.

4. **Notify the data owner** of the affected data store or system.

### If the transfer is benign but undocumented:

1. Work with the asset owner to document the legitimate use case.
2. Add a scheduled backup exception or update `sanctioned_services.csv` as appropriate.
3. Close the alert as a False Positive and log the tuning action in `tuning_log.md`.

---

## Step 4 — Escalation, Communication, and Documentation

**Goal:** Ensure appropriate stakeholders are informed and the incident is properly tracked.

### Escalation matrix:

| Condition | Escalate To | SLA |
|---|---|---|
| Confirmed exfiltration, non-sensitive data | SOC Tier 2 | 4 hours |
| Confirmed exfiltration, sensitive data (PII/IP/financial) | CISO + Legal | 1 hour |
| Critical asset involved | CISO + IT Director | Immediately |
| Evidence of insider threat | CISO + HR + Legal | Immediately |
| Evidence of external attacker | CISO + Incident Response team | Immediately |

### Documentation requirements:

- Open a formal incident ticket in the ticketing system with:
  - Alert ID, detection rule, alert timestamp
  - Source host, user, destination domain
  - Total bytes transferred, duration
  - All enrichment findings
  - Actions taken and their timestamps
  - Severity classification and escalation path taken
- Attach exported Splunk evidence.
- Record the incident outcome (confirmed exfiltration / false positive / undetermined).
- If regulatory data (PII, PHI, PCI) is potentially involved, notify the Compliance team within the required regulatory notification window.
