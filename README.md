# Detection Engineering for Data Loss Prevention

## Project Overview

This repository contains the final deliverable package for the CS-6399 Detection Engineering for Data Loss Prevention project by Pedram Shahbazi and Robert (Ash) Drake.

The project designs, implements, tests, and documents a Splunk-based detection engineering framework for identifying data exfiltration activity across multiple channels.

## Detection Use Cases

The framework includes four primary detection use cases:

1. UC1 — High-Volume Outbound Data Transfer
2. UC2 — Unsanctioned Cloud Storage Access
3. UC3 — DNS-Based Data Exfiltration
4. UC4 — Email-Based Data Exfiltration

## Repository Structure

```text
datasets/
  synthetic/     Synthetic exfiltration test dataset
  benign/        Benign validation dataset

detections/
  SPL detection rules, reusable macro, and threshold configuration

lookups/
  CSV lookup tables used for enrichment and exception handling

playbooks/
  Incident response playbooks for each detection use case

evaluation/
  Evaluation results, test catalog, and tuning log

```

## Key Artifacts

- `detections/uc1_high_volume.spl`
- `detections/uc2_unsanctioned.spl`
- `detections/uc3_dns_exfil.spl`
- `detections/uc4_email_exfil.spl`
- `detections/calc_entropy.spl`
- `detections/thresholds.conf`
- `lookups/asset_inventory.csv`
- `lookups/authorized_senders.csv`
- `lookups/sanctioned_services.csv`
- `lookups/unsanctioned_domains.csv`
- `playbooks/playbook_pb1.md`
- `playbooks/playbook_pb2.md`
- `playbooks/playbook_pb3.md`
- `playbooks/playbook_pb4.md`
- `evaluation/eval_results.md`
- `evaluation/tuning_log.md`
- `evaluation/test_catalog.xlsx`

## Evaluation Summary

The final evaluation demonstrated 100% recall across all simulated exfiltration scenarios and 94% overall precision. All four detection rules met the 30-second query performance target during testing.

## Privacy Note

All datasets used in this repository are synthetic or anonymized. No real production data is included.

