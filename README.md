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
