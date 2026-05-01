# Playbook PB4 — Email-Based Data Exfiltration

**Detection Rule:** UC4 — Email-Based Exfiltration (`uc4_email_exfil.spl`)  
**Version:** 1.0 | **Author:** Detection Engineering Project  
**Rule Variants:** A (Mass External Forwarding) | B (Large Attachment Volume)  
**Severity Levels Covered:** Low / Medium / High / Critical

---

## Overview

This playbook guides a SOC analyst when UC4 fires an alert for a user exhibiting email-based exfiltration indicators. Email is one of the most common channels for insider data theft, ranging from accidental misdirection to deliberate bulk forwarding before resignation or termination. Two rule variants are covered: mass forwarding to external recipients and bulk outbound attachment volume.

**Alert trigger summary (Rule A):** A user sent or forwarded more than 50 emails to external recipients in a single day, or contacted more than 30 unique external recipients.  
**Alert trigger summary (Rule B):** A user's total outbound attachment volume to external addresses exceeded 100 MB in a single day.

---

## Step 1 — Initial Validation

**Goal:** Confirm the alert represents genuine exfiltration risk and not a known authorized activity.

1. **Review the alert fields:**
   - Rule A: `user`, `external_sends`, `unique_recipients`, `unique_domains`, `subjects`
   - Rule B: `user`, `total_attach_mb`, `email_count`, `unique_recipients`

2. **Check the authorized senders list:**
   ```spl
   | inputlookup authorized_senders.csv | search user=<user>
   ```
   - If the user appears with an active (non-expired) entry → Review the approved limit. If within limit, close as authorized. If exceeding limit, escalate.

3. **Review the recipient list:**
   - Are all recipients clearly business contacts (recognizable company domains)?
   - Are any recipients personal email accounts (gmail.com, yahoo.com, hotmail.com, proton.me)?
   - Personal account recipients are a high-risk indicator.

4. **Review the email subjects** (from the `subjects` field):
   - Generic subjects ("test", "fwd:", or blank) paired with attachments are suspicious.
   - Business-context subjects ("Q4 board deck", "Project X files") require enrichment.

5. **Check the time of sending:**
   - Emails sent outside business hours, on weekends, or during the user's scheduled vacation are elevated risk.

**Decision point:**
- Authorized bulk sender within limits → Close. Document.
- Not authorized or exceeds approved limits → Continue to Step 2.

---

## Step 2 — Enrichment

**Goal:** Build a complete profile of the email activity and the user's intent.

1. **Retrieve the full email log for the user in the alert window:**
   ```spl
   index=email_logs user=<user> earliest=<first_seen> latest=<last_seen>
   | table _time action recipient subject attachment_size attachment_name
   | sort _time
   ```

2. **Identify the attachment types and file names** (if available in logs):
   - Archive files (`.zip`, `.7z`, `.tar.gz`) are high risk — often used to bundle multiple documents.
   - Database exports (`.csv`, `.xlsx`, `.sql`) are high risk.
   - Source code files in bulk are high risk for engineering companies.

3. **Check for auto-forwarding rules on the user's mailbox** (via mail admin console or audit log):
   ```spl
   index=email_logs user=<user> action=create_rule OR action=set_forwarding earliest=-7d
   | table _time action rule_name forward_to
   ```
   - An auto-forward rule to an external address is a strong indicator of premeditated exfiltration.

4. **Review the user's endpoint activity** (if EDR available):
   - Did the user access file shares, HR folders, or financial directories in the hours before sending?
   - Did the user compress files before sending?

5. **Review the user's recent access and HR status:**
   - Has the user given notice of resignation?
   - Are there any active HR performance proceedings?
   - Has the user's access been recently changed (e.g., upcoming offboarding)?

6. **Correlate with DLP policy alerts:**
   ```spl
   index=dlp_policy user=<user> earliest=-7d
   | stats count by policy_name action severity
   ```

7. **Establish a behavioral baseline:**
   ```spl
   index=email_logs user=<user> earliest=-30d latest=-1d
   | stats count as daily_sends by date_mday
   | stats avg(daily_sends) as avg_daily p95(daily_sends) as p95_daily
   ```
   - How far does today's volume deviate from the user's 30-day average?

---

## Step 3 — Containment and Remediation

**Goal:** Stop further email-based exfiltration; preserve evidence; engage HR appropriately.

### If auto-forwarding rule is discovered:

1. **Disable the forwarding rule immediately** via the mail admin console.
2. **Audit all mail forwarded** since the rule was created — estimate the data exposure window.

### If bulk manual sending is confirmed:

1. **Temporarily restrict the user's ability to send external email:**
   - Apply an outbound transport rule blocking the user's address from sending to external domains.
   - Coordinate with IT to apply the restriction without alerting the user prematurely.

2. **Place a legal hold on the user's mailbox:**
   - Engage the legal team to initiate an eDiscovery hold.
   - This preserves all sent items and attachments for forensic review.
   - Do not allow the user to delete items while the hold is in effect.

3. **Preserve evidence:**
   - Export the relevant sent items and email audit logs to the secure evidence store.
   - Do not modify or delete any mail server records.

4. **Coordinate the user interview with HR and Legal:**
   - Do not confront the user directly without HR and Legal alignment.
   - HR should lead the interview; Security provides factual evidence only.
   - The outcome of the interview determines whether account suspension is required.

### If accidental misdirection or benign bulk send is determined:

1. Confirm with the user's manager that the activity was authorized or accidental.
2. Add the user to `authorized_senders.csv` with an appropriate limit and expiry if the activity is recurring and legitimate.
3. Close the alert as a false positive or authorized exception. Document the determination.

---

## Step 4 — Escalation, Communication, and Documentation

### Escalation matrix:

| Condition | Escalate To | SLA |
|---|---|---|
| First offense, small volume, no sensitive data | Manager + SOC Tier 2 | 8 hours |
| Sensitive data (PII/IP/financial) involved | CISO + Legal + HR | 1 hour |
| Auto-forwarding rule discovered | CISO + HR + Legal | 1 hour |
| Resignation notice or offboarding in progress | CISO + HR + Legal | Immediately |
| C-suite or executive user | CISO + Board as appropriate | Immediately |
| Volume exceeds 1 GB or 500+ recipients | CISO + Legal + Compliance | Immediately |

### Regulatory notification:

- If the forwarded data includes PII, PHI, or PCI-regulated data, notify the Compliance team within the required regulatory notification window.
- The Compliance team will determine whether external breach notification obligations apply.

### Documentation requirements:

- Open an incident ticket recording: alert ID, rule variant (A or B), user, volume, recipient list summary, attachment types, enrichment findings, all actions taken and their timestamps.
- Attach the exported email audit logs and the behavioral baseline comparison.
- Record the final determination: deliberate exfiltration / accidental / authorized exception / indeterminate.
- If an auto-forward rule was discovered, document: when it was created, how long it was active, estimated number of emails forwarded, and remediation steps taken.
- File a post-incident report within 5 business days of closure for any High or Critical severity case.
