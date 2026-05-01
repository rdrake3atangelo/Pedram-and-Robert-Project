# Evaluation Results
## DLP Detection Engineering Project — Final Evaluation Report

**Evaluation Period:** Weeks 10–12 (Phases 5 & 6)  
**Dataset:** Synthetic dataset (24,395 events) + Benign validation dataset (6,062 events)  
**Rules Evaluated:** UC1, UC2, UC3, UC4 (four detection use cases, six SPL rules total)  
**Playbooks Evaluated:** PB1, PB2, PB3, PB4

---

## 1. Quantitative Detection Performance

### 1.1 Per-Use-Case Metrics

| Use Case | Description | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| UC1 | High-Volume Outbound Transfer | 4 | 0 | 0 | 100% | 100% | 1.00 |
| UC2 | Unsanctioned Cloud Storage Access | 6 | 0 | 0 | 100% | 100% | 1.00 |
| UC3 | DNS-Based Exfiltration | 2 | 0 | 0 | 100% | 100% | 1.00 |
| UC4 | Email-Based Exfiltration | 3 | 1 | 0 | 75% | 100% | 0.86 |
| **Overall** | **All Use Cases** | **15** | **1** | **0** | **94%** | **100%** | **0.97** |

**Notes:**
- UC1 and UC2 fired simultaneously on 2 of the 4 UC1 true positives (exfiltration to unsanctioned
  domains), as designed. These are counted as distinct detections serving complementary coverage.
- The single UC4 false positive (user "frank") was caused by a legitimate bulk email campaign
  not yet recorded in `authorized_senders.csv`. The lookup was updated after the test (see TL-02
  in tuning_log.md). This case is retained in results as-is to accurately represent the
  pre-mitigation state and demonstrate the exception mechanism.

---

### 1.2 Unit-Level Test Results

| TC-ID | Use Case | Expected Alerts | Actual Alerts | Pass/Fail |
|---|---|---|---|---|
| TC-01 | UC1 | 0 | 0 | Pass |
| TC-02 | UC1 | 1 | 1 | Pass |
| TC-03 | UC1 | 0 | 0 | Pass |
| TC-04 | UC1 | 1 | 1 | Pass |
| TC-05 | UC1 | 1 | 1 | Pass |
| TC-06 | UC1 | 0 | 0 | Pass |
| TC-07 | UC2 | 1 | 1 | Pass |
| TC-08 | UC2 | 0 | 0 | Pass |
| TC-09 | UC2 | 6 | 6 | Pass |
| TC-10 | UC2 | 1 | 1 | Pass |
| TC-11 | UC2 | 0 | 0 | Pass |
| TC-12 | UC3 | 0 | 0 | Pass (key entropy tuning result) |
| TC-13 | UC3 | 1 | 1 | Pass |
| TC-14 | UC3 | 1 | 1 | Pass |
| TC-15 | UC3 | 1 | 1 | Pass |
| TC-16 | UC3 | 0 | 0 | Pass |
| TC-17 | UC4 | 1 | 1 | Pass |
| TC-18 | UC4 | 1 | 1 | Pass |
| TC-19 | UC4 | 0 | 0 | Pass (exception correctly suppressed alert) |
| TC-20 | UC4 | 0 | 0 | Pass |
| TC-21 | UC4 | 1 | 1 | Pass |
| TC-22 | UC4 | 1 | 1 | Pass |
| TC-23 | UC4 | 0 | 1 | **FP — Managed** (authorized_senders.csv updated) |

**Unit test pass rate: 22/23 (96%) — 1 managed FP**

---

### 1.3 Scenario-Based Test Results

| Scenario | Vector(s) | Expected | Actual | Playbook Correct | Result |
|---|---|---|---|---|---|
| S1 — Insider uploads archive to Dropbox | UC1 + UC2 | 2 alerts | 2 alerts | Yes (PB1 + PB2) | Pass |
| S2 — Employee bulk-forwards emails pre-resignation | UC4 | 1 alert | 1 alert | Yes (PB4) | Pass |
| S3 — Compromised host runs DNS tunnel | UC3 | 1 alert | 1 alert | Yes (PB3) | Pass |
| S4 — Staged sync to WeTransfer over 3 hours | UC1 + UC2 | 2 alerts | 2 alerts | Yes (PB1 + PB2) | Pass |
| S5 — Mass attachment send to personal Gmail | UC4 | 1 alert | 1 alert | Yes (PB4) | Pass |

**Scenario test pass rate: 5/5 (100%) — 100% detection coverage, 100% correct playbook routing**

---

### 1.4 Baseline / False-Positive Test Results

| Rule | Benign Events Tested | FP Count | FP Rate | Status |
|---|---|---|---|---|
| UC1 — High-Volume Outbound | 2,500 | 0 | 0.0% | Pass |
| UC2 — Unsanctioned Domain | 2,500 | 0 | 0.0% | Pass |
| UC3 — DNS Exfiltration (tuned) | 2,000 | 0 | 0.0% | Pass |
| UC4 — Email Exfiltration | 1,062 | 1 | 0.094% | Managed |

**Overall benign false-positive rate: 1 / 8,062 = 0.012%**

The single false positive (frank, UC4) is fully characterised:
- **Root cause:** Legitimate bulk email campaign not yet entered in authorized_senders.csv.
- **Mitigation:** User added to exception lookup; alert correctly suppressed on retest.
- **Residual risk:** If authorized_senders.csv is not kept current, similar FPs will recur.
  Quarterly review cadence and named lookup owner are recommended operational controls.

---

### 1.5 Query Performance Benchmarks

| Detection Rule | 1-Hr Window | 24-Hr Window | SLA (30 s) Met? |
|---|---|---|---|
| UC1 — High-Volume Outbound | 1.4 s | 8.2 s | Yes |
| UC2 — Unsanctioned Domain | 1.1 s | 6.7 s | Yes |
| UC3 — DNS Exfiltration | 2.3 s | 14.1 s | Yes |
| UC4 — Email Exfiltration | 1.6 s | 9.4 s | Yes |

All four detection rules met the 30-second SLA for a 24-hour look-back window on the test
dataset volume (~24,000 events). UC3 exhibits the highest execution time due to per-event
entropy computation. For production environments ingesting >1M DNS events per day, pre-computing
entropy at index time via a scripted input is recommended to reduce the 24-hour query time
to an estimated 4–5 seconds.

---

## 2. Qualitative Operational Assessment

### 2.1 Alert Clarity

All four detection rules produce structured output fields that provide an analyst with
sufficient context to form an initial triage hypothesis without issuing additional Splunk
queries. Key fields present in all alerts:

- User identity and source host
- Destination (domain, IP, or recipient)
- Volume or event count metric
- Severity classification
- Timestamp range (first_seen / last_seen)

**Rating:** ★★★★★ — All alert outputs rated as operationally clear in analyst walkthrough.

### 2.2 Playbook Usability

The four playbooks were walked through by a simulated analyst against each of the five
test scenarios. Findings:

- All four playbooks covered the expected triage and containment actions without gaps.
- Decision points at each step were found to be clearly articulated.
- Enrichment SPL queries embedded in the playbooks executed correctly against the test data.
- Minor language clarifications were incorporated after the walkthrough into the final
  playbook versions (see playbooks/ directory).

One observation: Playbook PB3 (DNS Exfiltration) benefited significantly from including
the visual distinction between tunneling subdomains (random-looking base64) and legitimate
hostnames (structured, readable). Analysts found this guidance the most practically useful
addition to the playbook.

**Rating:** ★★★★☆ — Excellent usability; one minor improvement made post-walkthrough.

### 2.3 Threshold Transparency

All thresholds are expressed as named macros in `thresholds.conf`, each accompanied by:
- The numeric default value
- The behavioral observation that motivated the value
- The recommended recalibration conditions
- Whether a higher or lower value is appropriate for specific environment types

**Rating:** ★★★★★ — Full transparency; all thresholds documented with rationale.

### 2.4 Modularity and Maintainability

- SPL rules use macros for all thresholds: no hardcoded values in detection logic.
- Lookup tables are stored as CSVs in version control with defined review cadence.
- The calc_entropy macro is decoupled from UC3 and reusable in future detection rules.
- All artefacts organised in a structured Git repository directory layout.

**Rating:** ★★★★★ — Fully modular; ready for production deployment with SOC tooling.

### 2.5 Non-Functional Requirements Assessment

| Requirement | Target | Result | Met? |
|---|---|---|---|
| Performance | All queries < 30 s (24-hr window) | Max 14.1 s | Yes |
| Scalability | Efficient aggregations; no unnecessary complexity | Macros + summary index recommendation | Yes |
| Reliability | Consistent detection; error handling documented | All rules stable across repeated test runs | Yes |
| Explainability | Transparent logic; thresholds documented | Full documentation in thresholds.conf | Yes |
| Maintainability | Modular; version-controlled | Git repo; CSV lookups; macros | Yes |
| Compliance & Privacy | Anonymized or synthetic data only | No real production data used | Yes |
| Ingestion Volume | < 500 MB/day (license) | Synthetic dataset within limit | Yes |
| Uptime / Delay | 100% uptime; < 5 min ingestion delay | Met in lab environment | Yes |

**All 8 non-functional requirements met.**

---

## 3. Key Findings and Lessons Learned

### 3.1 Multi-Signal Detection Outperforms Single-Signal Rules
UC3 demonstrated that combining three signals (query count, subdomain length, and entropy)
produces substantially better precision than any individual signal alone. The monitoring
agent (10.0.0.7) passed on count and length but failed on entropy — a distinction a
two-signal rule would have missed.

### 3.2 Exception Lookup Tables Are Operationally Critical
The UC4 false positive (frank) was entirely predictable from an operational standpoint.
Legitimate high-volume email users (sales, marketing) will periodically exceed any reasonable
threshold. The exception mechanism (authorized_senders.csv) effectively mitigates this, but
only if the lookup is kept current. This is an ongoing operational commitment, not a one-time setup.

### 3.3 Severity Banding Improves Analyst Prioritisation
Adding severity banding to UC1 (TL-05) — Critical / High / Medium / Low based on transfer
volume — meaningfully improved analyst walkthrough ratings for triage clarity. Flat severity
alerts require analysts to re-examine the underlying data to prioritise; banded severity
alerts allow immediate prioritisation at the alert list level.

### 3.4 Synthetic Dataset Design Requires Careful Calibration
Embedding exfiltration events that are too obvious (e.g., single 10 GB transfer in a
dataset of 1 KB transfers) does not test detection logic — it tests that the rule runs.
Effective synthetic data requires benign events that reflect realistic enterprise distributions
so that exfiltration events stand out for the quantitative reasons the rule was designed to
detect. The datasets in this project were designed with this principle in mind, though they
remain a simplification of real enterprise traffic.

### 3.5 Version Control for SPL Is Practically Valuable
Maintaining all SPL rules and lookup tables in Git provided a clear audit trail for every
tuning decision. On two occasions (TL-03 and TL-07), the ability to compare the "before"
and "after" versions of a rule side-by-side in Git diff view saved significant time in
confirming that changes had the intended and no unintended effects.

---

## 4. Limitations

1. **Synthetic data dependency:** All testing was conducted on purpose-built datasets. Detection
   performance in production environments — with real traffic diversity, noise, and edge cases —
   may differ. In particular, false-positive rates in production are likely to be higher until
   exception lookups are fully populated from observed normal activity.

2. **Static thresholds:** All detection rules use static thresholds. In production environments
   with seasonal patterns (e.g., year-end financial reporting, product launch periods), static
   thresholds calibrated to average baseline behaviour may generate elevated false positives
   during peak activity periods. Dynamic baselines (rolling percentiles) would address this.

3. **Single-organisation profile:** Thresholds, lookup tables, and playbook assumptions reflect
   the implied organisational profile of the synthetic dataset. Real-world deployment requires
   recalibration against the target organisation's actual baselines.

4. **SOAR integration absent:** Playbooks are executed semi-manually. Without automation,
   response consistency depends on analyst availability and discipline under alert load.

5. **No lateral movement correlation:** The framework detects exfiltration-phase activity only.
   Correlating with credential compromise, privilege escalation, or lateral movement signals
   would enable earlier detection in the attack lifecycle.

---

## 5. Recommendations for Production Deployment

1. **Run in monitor-only mode for 30 days** before enabling active alerting. Use this period
   to calibrate thresholds against real baseline traffic and pre-populate exception lookup tables.

2. **Assign named ownership of each lookup table.** Each CSV should have a designated owner
   and a documented quarterly review date to prevent staleness.

3. **Integrate with SOAR.** Priority automation: domain blocking (PB1/PB2), account session
   revocation (PB3), mailbox legal hold initiation (PB4).

4. **Implement dynamic baselines** using Splunk MLTK for UC1 (per-host outbound volume) and
   UC4 (per-user email volume) to reduce false positives during predictable activity spikes.

5. **Supplement with real-world PCAP or log data** (appropriately anonymised) to validate
   detection performance beyond the synthetic dataset and confirm entropy thresholds are
   appropriate for the production DNS environment.
