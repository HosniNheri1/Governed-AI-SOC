# Scope Statement

Version 0.1 | Day 1

## Purpose
Extend an existing SOC lab with an ML scoring service, and govern that service as an AI system (ISO/IEC 42001) while the surrounding SOC is mapped to ISO/IEC 27001:2022.

## In scope
- Attack types: Nmap SYN, version and script scans (including a slow scan); Hydra brute force on SSH, FTP and HTTP.
- Benign traffic: normal logins (including some failed ones), web requests, file transfers.
- Systems: attacker VM (Kali), victim hosts, edge and internal Suricata sensors, Splunk, Shuffle, one ML service.
- ISO 27001 controls exercised by the lab: 8.15, 8.16, 8.20, 8.22, 8.5, 5.24 to 5.28; optional 8.8 and 8.29.
- ISO 42001 elements exercised by the model: AI policy, AI risk assessment, AI system impact assessment, model card, lifecycle and monitoring plan, human oversight, dataset provenance.

## Out of scope
- Real production data or real third-party networks.
- Certification or claims of conformity.
- Full Annex A coverage of either standard.
- Adversarial-ML experiments beyond a documented risk entry.
- Automatic blocking (blocking is simulated and requires human approval).

## Ethics and safety
All attacks are run only against lab hosts that I own, on an isolated network with no route to third parties. This statement is repeated in the final report.

## Assumptions (confirm or change)
- A1: The existing Docker Swarm lab (Splunk, Suricata, Shuffle) still runs.
- A2: Work is individual, about 10 days.
- A3: Deliverables are in English.
- A4: Dataset is lab-generated; a public dataset is optional and only if time allows.

## Success criteria
See docs/01-research-design.md.

## Constraints and cut-lines
Cut in this order if behind: Isolation Forest, public-dataset test, HTTP brute force, controls 8.8 and 8.29, demo video length.
Never cut: session-based split, comparison against Suricata alone, traceability matrix.
