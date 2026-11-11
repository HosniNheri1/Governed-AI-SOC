# ISMS Scope and Context — Governed AI-Assisted SOC (lab scope)

**Status:** draft for review. Owner decisions of 2026-11-11 are applied: sole contributor, `correlation-engine` out of scope, Shuffle runs in the cloud.
**Standard:** ISO/IEC 27001:2022 clauses 4.1 to 4.3. Implemented on a defined scope, not certified.
**Based on:** `00-scope.md` (Day 1), `attacks/playbook.md` (Day 2), `risk_register.md`, `soa_partial.md`.
**Version / date / owner:** v0.1 / 2026-11-11 / Hosni Nheri

## 1. Context of the organization (clause 4.1)

The "organization" is a single-person academic lab project. The ISMS exists to protect the lab's information and to show how a SOC and an AI detection model are governed on a small scale.

| Type | Issue | Effect on the ISMS |
|---|---|---|
| Internal | One person (Hosni Nheri) holds every role: owner, analyst, approver of the simulated block, model validator | No independent review, no segregation of duties. The analyst who approves the block is the person who owns the system (R-03, audit finding F7) |
| Internal | Ten-day schedule | Scope is deliberately partial; cut-lines are in `00-scope.md` |
| Internal | Small synthetic dataset (32 sessions) | Detection metrics do not transfer to production (R-01, R-02, R-05) |
| Internal | Services started by hand, ingestion stops between sessions | Alerts may never fire (R-08) |
| External | Dependence on third-party services: Shuffle (cloud-hosted SaaS), ngrok tunnel, AbuseIPDB, VirusTotal, Emerging Threats ruleset, Splunk and Docker images | Availability and exposure are outside the lab's control. Alert data leaves the lab for the Shuffle cloud, and a lab service is reachable from the Internet through the tunnel (R-09) |
| External | Academic assessment and public portfolio | Documents are read by reviewers and recruiters, so overclaiming is a real risk (wording rules in the roadmap) |
| External | Law and ethics on attack tools | Attacks only against hosts the owner controls, on the lab network |

## 2. Interested parties and requirements (clause 4.2)

| Party | Relevant requirement | Addressed by |
|---|---|---|
| Lab owner (student) | Working, reproducible lab; honest results | Playbook, collection log, evaluation report |
| Academic supervisor / jury | Method, evidence, honest limits | Traceability matrix, gap analysis |
| Recruiters and portfolio readers | Accurate claims, no "certified" wording, no leaked secrets or client data | Wording rules, evidence masking (5.28), audit findings F4 and F6 |
| Third-party service providers (Shuffle cloud, ngrok, AbuseIPDB, VirusTotal, Proofpoint ET Open, image registries) | Terms of use and rate limits; API keys kept secret. Shuffle receives alert content (IP addresses, event fields) | Key handling, masked evidence, synthetic data only, R-09 |
| Dataset suppliers (only if a public dataset is used) | Licence and citation; known label issues (CIC-IDS2017) | 42001 data provenance (Day 8) |

## 3. Scope of the ISMS (clause 4.3)

### 3.1 In scope
Information and systems below, used for attack simulation, detection, response and evaluation.

| Asset | Description | Type | Owner | Classification | Linked risks |
|---|---|---|---|---|---|
| `victim1` (172.30.0.10) | Victim container: SSH 22, FTP 21, Apache 80, Python login endpoint 8080 | System | Lab owner | Internal (intentionally weak) | R-01, R-03, R-04 |
| Kali host (172.30.0.1) | Attacker VM, also the gateway of `br-victims` | System | Lab owner | Internal | R-03 |
| `suricata-internal`, `suricata-edge` | Sensors (host network mode), local rules 9000001 to 9000004 plus ET ruleset | System | Lab owner | Internal | R-01, R-02, R-08 |
| Splunk container | SIEM, port 8000, alert on SSH brute force | System | Lab owner | Internal | R-03, R-08, R-09 |
| Shuffle workflow | SOAR hosted in the **Shuffle cloud** (outside the lab host): webhook, score, enrichment, `analyst-approval`, simulated block. The workflow and its stored API keys live at the provider | System (external service) | Lab owner (account), provider (platform) | Internal | R-03, R-09 |
| ML scoring service | FastAPI endpoint on the lab host, called from the Shuffle cloud through a tunnel during tests | System | Lab owner | Internal | R-03, R-05, R-09 |
| Logs | Suricata `eve.json`, victim auth logs | Information | Lab owner | Internal | R-04, R-08 |
| Dataset and collection log | 32 labeled sessions, `collection_log_clean.csv` | Information | Lab owner | Internal | R-05, R-06 |
| Trained model and notebooks | Random Forest, features, seed 42 | Information | Lab owner | Internal | R-05, R-06, R-07 |
| Secrets | Splunk password, API keys (AbuseIPDB, VirusTotal), webhook URL, tunnel URL | Information | Lab owner | **Confidential** | R-09 |
| Evidence and GRC documents | `evidence/`, `grc/27001/`, `grc/42001/` | Information | Lab owner | Internal; public only after masking | R-03 |

### 3.2 Out of scope
Production systems, real third-party networks and real data. Certification or conformity claims. All other Annex A controls. Adversarial-ML experiments beyond a documented risk. Automatic blocking (simulated, with human approval).

`correlation-engine` (172.19.0.2) is **out of scope**: the owner confirmed it is not part of this project. It is a leftover name in the playbook from the earlier funnel-attack work, and the reference should be removed from the playbook and the architecture diagram. `coderunner` is also unrelated and left alone.

### 3.3 Boundary, interfaces and dependencies
- **Inside the boundary:** the `br-victims` network (172.30.0.0/24) with the victim, the attacker/gateway and the sensors, plus Splunk and the scoring service on the lab host.
- **Outside the boundary:** the Shuffle workflow, hosted in the Shuffle cloud. It is a supplier system the lab depends on, not a lab component.
- **Interfaces that cross the boundary:**
  - Splunk alert webhook to the Shuffle cloud (alert content leaves the lab).
  - Shuffle cloud to the scoring service through the ngrok tunnel (a lab service is exposed to the Internet while the tunnel is open).
  - AbuseIPDB and VirusTotal calls, made from the Shuffle cloud with API keys stored there.
  - Package and image downloads, and ET ruleset updates.
- **Data sent out:** synthetic lab traffic only (private addresses, scripted attack events). No real personal or production data.
- **Protection required on the tunnel:** an API key or token on the FastAPI endpoint, the tunnel open only during tests, and the Splunk default password rotated before any exposure (audit finding F4).
- **Dependency on suppliers:** the lab cannot run the SOAR workflow, the enrichment step or the tunnel without them (R-09, 42001 third-party management). Suggested R-09 wording: exposure of the tunnel and dependence on a SaaS provider.

## 4. Statement to correct in `00-scope.md`

`00-scope.md` says attacks run "on an isolated network with no route to third parties". The management side of the lab does have outside routes (tunnel, webhook, enrichment APIs, updates). Proposed wording, to repeat in the final report:

> All attacks are run only against lab hosts that I own. The attack network (`br-victims`, 172.30.0.0/24) is isolated from third-party systems. The management components have limited outside connections: Splunk and the scoring service run locally and are reached through a test tunnel, while the Shuffle workflow runs in the Shuffle cloud and calls enrichment services. These connections are listed in the ISMS scope document.

## 4b. Roles in a one-person ISMS
Hosni Nheri is lab owner, analyst, approver and model validator. This is a stated limitation. Compensating measures: every decision is logged in Shuffle with a timestamp, a decision record gives the reasoning, and the log is reviewed after each test session. These measures do not replace independent review.

## 5. Assumptions and limits
- No other contributor works on this repository (confirmed by the owner, 2026-11-11).
- The lab runs on one host and has no production use.
- Statuses and addresses come from the Day 2 playbook; changes after 2026-11-06 are not reflected.
- This document is not an ISMS certificate, a statement of compliance or a security guarantee.

## 6. Review
Review when a component, address or external service changes, and before publication. Date and change note: **[to fill]**.
