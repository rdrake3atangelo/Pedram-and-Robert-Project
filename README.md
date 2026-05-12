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
  synthetic_dataset/     Synthetic exfiltration test dataset
  benign_dataset/        Benign validation dataset
  generate_datasets/     Python file

docs/
  project_proposal/  Original project proposal
  project_design/    Project design document
  presentation/      Final presentation slides
  progress_reports/  Progress reports 1–5

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
- `docs/project_proposal/Proposal.pdf`
- `docs/project_design/Project Design.pdf`
- `docs/presentation/DLP Presentation.pptx`
- `docs/progress_reports/Progress Report 1.pdf`
- `docs/progress_reports/Progress Report 2.pdf`
- `docs/progress_reports/Progress Report 3.pdf`
- `docs/progress_reports/Progress Report 4.docx`
- `docs/progress_reports/Progress Report 5.pdf`

## Evaluation Summary

The final evaluation demonstrated 100% recall across all simulated exfiltration scenarios and 94% overall precision. All four detection rules met the 30-second query performance target during testing.

## Privacy Note

All datasets used in this repository are synthetic or anonymized. No real production data is included.

