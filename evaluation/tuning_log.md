# Detection Tuning Log
## DLP Detection Engineering Project

**Purpose:** Chronological record of all threshold adjustments, rule changes, and lookup
updates made during implementation and testing. Each entry documents the trigger, the
change made, and the measured impact on precision and recall.

---

## Log Format

Each entry follows this structure:

```
### TL-XX — [Date] — [Use Case] — [Change Type]
- **Trigger:** What prompted the change
- **Change:** What was modified (threshold / logic / lookup)
- **Before:** Previous value or behaviour
- **After:** New value or behaviour
- **Impact:** Measured effect on TP / FP / FN counts
- **Status:** Applied / Reverted / Pending
```

---

## Tuning Entries

---

### TL-01 — 2026-03-10 — UC4 (Email) — Threshold Adjustment

- **Trigger:** During unit-level testing, an initial threshold of 20 external sends per day
  generated multiple false positive alerts against marketing and sales team members in the
  benign dataset. Users "frank" (marketing) and a simulated sales account each exceeded 20
  sends during normal outreach activity.
- **Change:** Raised `email_send_threshold` macro from 20 to 50 external sends per day.
- **Before:** `email_send_threshold = 20` — generated 4 false positives in benign dataset.
- **After:** `email_send_threshold = 50` — 1 false positive remaining (frank, sales campaign).
- **Impact:**
  - False Positives: 4 → 1 (75% reduction)
  - True Positives: 3 → 3 (unchanged; all confirmed exfiltration cases exceeded 50)
  - False Negatives: 0 (no change)
- **Status:** Applied

---

### TL-02 — 2026-03-10 — UC4 (Email) — Lookup Update

- **Trigger:** After TL-01, one false positive remained: user "frank" (marketing),
  who runs legitimate quarterly bulk email campaigns. Raising the threshold further
  would reduce the rule's sensitivity for genuine exfiltration cases.
- **Change:** Added frank@company.com to `authorized_senders.csv` with an approved
  send limit of 500 and an expiry date of 2026-06-30.
- **Before:** frank not listed in authorized_senders.csv.
- **After:** frank listed with approved limit; UC4 exception logic correctly suppresses alert.
- **Impact:**
  - False Positives: 1 → 0
  - True Positives: 3 → 3 (unchanged)
- **Status:** Applied
- **Note:** This entry highlights the operational need to keep authorized_senders.csv
  current. A quarterly review process is recommended.

---

### TL-03 — 2026-03-14 — UC3 (DNS) — Entropy Signal Added

- **Trigger:** During scenario-based testing, host 10.0.0.7 (network monitoring agent)
  generated a borderline alert. The host produced 412 DNS queries per hour with an average
  subdomain length of 31.4 characters — exceeding the query count threshold of 300 and the
  subdomain length threshold of 40 (borderline). When tested against the original two-signal
  rule (count + length only), the host triggered an alert, constituting a false positive.
- **Change:** Added Shannon entropy as a third required condition in the UC3 rule.
  Implemented the `calc_entropy` macro. Set `dns_entropy_threshold = 3.5`.
- **Before:** UC3 rule: `query_count > 300 AND avg_subdomain_len > 40`
  - Result on 10.0.0.7: Alert generated (False Positive)
- **After:** UC3 rule: `query_count > 300 AND avg_subdomain_len > 40 AND avg_entropy > 3.5`
  - 10.0.0.7 measured avg_entropy = 2.87 → below threshold → no alert
  - 10.0.0.14 measured avg_entropy = 4.21 → above threshold → alert confirmed
  - 10.0.0.31 measured avg_entropy = 4.08 → above threshold → alert confirmed
- **Impact:**
  - False Positives: 1 → 0 (100% reduction)
  - True Positives: 2 → 2 (unchanged)
  - False Negatives: 0 (unchanged)
- **Status:** Applied

---

### TL-04 — 2026-03-14 — UC3 (DNS) — Query Count Threshold Adjustment

- **Trigger:** Following TL-03 (entropy signal added), reviewed whether the query count
  threshold of 300 was still appropriate. With entropy now required, a lower count threshold
  could be used without increasing FP risk, potentially improving sensitivity for low-and-slow
  DNS tunneling.
- **Change:** Evaluated lowering `dns_query_count_threshold` from 300 to 200.
- **Before:** `dns_query_count_threshold = 300`
- **After (evaluated):** `dns_query_count_threshold = 200`
- **Impact at 200:**
  - True Positives: 2 → 2 (unchanged)
  - False Positives: 0 → 0 (entropy condition prevents FP from monitoring agent)
  - No change in outcomes for current dataset.
- **Decision:** Retaining threshold at 300 for the current environment. The 200-query level
  would add sensitivity for low-rate tunneling but increases noise risk in production
  environments with many monitoring tools. Documented as a recommended tuning option for
  environments where low-and-slow DNS exfiltration is a primary threat model concern.
- **Status:** Evaluated — Not Applied (retained at 300)

---

### TL-05 — 2026-03-18 — UC1 (High-Volume) — Severity Banding Added

- **Trigger:** Initial UC1 rule returned all alerts at the same priority level regardless of
  transfer volume. During analyst walkthrough of PB1, reviewers noted difficulty triaging
  a 510 MB transfer and a 5 GB transfer as equally urgent.
- **Change:** Added severity banding logic to UC1 output:
  - `> 5 GB` → Critical
  - `> 1 GB` → High
  - `> 500 MB` → Medium
  - At threshold → Low
- **Before:** All UC1 alerts assigned severity = "High" uniformly.
- **After:** Severity assigned dynamically based on transfer volume.
- **Impact:**
  - No change to alert volume (TP/FP counts unchanged).
  - Analyst walkthrough rated playbook triage clarity as "significantly improved" after change.
- **Status:** Applied

---

### TL-06 — 2026-03-20 — UC2 (Unsanctioned Domain) — Lookup Expansion

- **Trigger:** During scenario testing, a simulated exfiltration to `bashupload.com` and
  `0x0.st` (common attack-tool upload destinations) was not flagged because these domains
  were not in the initial `unsanctioned_domains.csv`.
- **Change:** Added 5 new domains to unsanctioned_domains.csv:
  - `temp.sh`, `bashupload.com`, `0x0.st`, `gofile.io`, `uploadfiles.io`
- **Before:** unsanctioned_domains.csv contained 15 entries.
- **After:** unsanctioned_domains.csv contains 20 entries.
- **Impact:**
  - No change to existing test results (these domains were not in the current synthetic dataset).
  - Increases coverage for future test scenarios involving CLI-style upload tools.
- **Status:** Applied

---

### TL-07 — 2026-03-22 — UC4 (Email) — Recipient Threshold Added

- **Trigger:** During review of the UC4 results, recognised that an attacker could evade
  the `email_send_threshold` of 50 by sending 49 emails each to a large but different set of
  recipients — a broadcast-style exfiltration pattern not caught by count alone.
- **Change:** Added `unique_recipients` as a second triggering condition in Rule A:
  `external_sends > 50 OR unique_recipients > 30`.
- **Before:** Rule A: `external_sends > email_send_threshold`
- **After:** Rule A: `external_sends > email_send_threshold OR unique_recipients > email_recipient_threshold`
- **Impact:**
  - True Positives: 3 → 3 (unchanged; existing cases exceeded both conditions)
  - False Positives: 0 → 0 (no benign user contacted > 30 unique external recipients)
  - Detection coverage: Improved for broadcast-style exfiltration scenarios.
- **Status:** Applied

---

## Summary Table

| Entry | Date | Use Case | Change Type | TP Δ | FP Δ | FN Δ | Status |
|---|---|---|---|---|---|---|---|
| TL-01 | 2026-03-10 | UC4 | Threshold raised (20→50 sends) | 0 | -3 | 0 | Applied |
| TL-02 | 2026-03-10 | UC4 | authorized_senders.csv updated | 0 | -1 | 0 | Applied |
| TL-03 | 2026-03-14 | UC3 | Entropy signal added (3.5 threshold) | 0 | -1 | 0 | Applied |
| TL-04 | 2026-03-14 | UC3 | Count threshold evaluated (300→200) | 0 | 0 | 0 | Not Applied |
| TL-05 | 2026-03-18 | UC1 | Severity banding added | 0 | 0 | 0 | Applied |
| TL-06 | 2026-03-20 | UC2 | Unsanctioned domain list expanded | 0 | 0 | 0 | Applied |
| TL-07 | 2026-03-22 | UC4 | Unique recipient condition added | 0 | 0 | 0 | Applied |

**Net tuning effect:** FP count reduced from 5 (pre-tuning) to 1 (post-tuning) — an 80% reduction.
All true positives retained throughout tuning process (0 TPs sacrificed).
