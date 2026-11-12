# Governed AI-Assisted SOC

An ML detection layer added to a Suricata / Splunk / Shuffle lab, compared against Suricata rules alone on network scans and brute force, and governed as an AI system (ISO/IEC 42001) inside a SOC mapped to ISO/IEC 27001:2022.

> **Scope and honesty note.** Everything here was built and measured in one isolated lab, on a small synthetic dataset. The ISO work is *implemented on a defined lab scope*. It is **not** a certification and makes no claim of conformity. Results do not transfer directly to production. See [Known limitations](#known-limitations).

## Research question

Does an ML detector add value over Suricata rules alone for detecting scans and brute force in a small network, and how can it be governed?

## View the portfolio>>>>>https://hosninheri1.github.io/Governed-AI-SOC/docs/index.html

## Main result

Dataset: 32 labeled sessions collected on 2026-11-07 (8 benign, 6 Nmap SYN scan, 7 SSH, 6 FTP and 5 HTTP brute force). Each number counts whole sessions.

| Detector | Precision | Recall (95% Wilson CI) | F1 | FPR (95% Wilson CI) | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Suricata alone (local rules 9000001-9000004) | 1.000 | 0.583 (0.388-0.755) | 0.737 | 0.000 (0.000-0.324) | 14 | 0 | 10 | 8 |
| Model alone (Random Forest, out-of-fold) | 1.000 | 1.000 (0.862-1.000) | 1.000 | 0.000 (0.000-0.324) | 24 | 0 | 0 | 8 |
| Hybrid OR (either detector flags) | 1.000 | 1.000 (0.862-1.000) | 1.000 | 0.000 (0.000-0.324) | 24 | 0 | 0 | 8 |
| Hybrid AND (both must agree) | 1.000 | 0.583 (0.388-0.755) | 0.737 | 0.000 (0.000-0.324) | 14 | 0 | 10 | 8 |

Hybrid AND equals Suricata alone here because every session Suricata flagged was also flagged by the model. Source: `data/day5_evaluation_summary_v2.csv`.

**What this supports, and what it does not.**
- Suricata missed 10 of 24 attacks. All 10 are explained by one mechanism: the local rules use fixed thresholds (`count 5, seconds 60` for brute force; 20 SYNs in 5 s for scans), so low-and-slow activity never crosses them. Every Hydra run with `-t1` or `-t2` (9 sessions) and the one `-T2` Nmap scan were missed; every run with `-t4` or `-t6` (9 sessions) was caught.
- The model uses session-level features (duration, distinct ports, FTP failure rate, HTTP POST count) and caught all 10. On this data the hybrid reduces missed detections. This does **not** show that the model replaces Suricata.
- With 24 attack and 8 benign sessions the intervals are wide: a recall of 24/24 has a 95% Wilson lower bound of 0.862, and an FPR of 0/8 has an upper bound of 0.324. Point estimates of 1.000 and 0.000 should not be quoted without these intervals.
- The false-positive side of the hypothesis was not tested: Suricata already had FPR 0 on this data.

Details: [`docs/day5_evaluation_report.md`](docs/day5_evaluation_report.md).

## Architecture

```
Kali (Nmap, Hydra) --> br-victims (172.30.0.0/24) --> victim1 (SSH, FTP, HTTP)
                              |
                       Suricata sensors --> eve.json --> Splunk
                                                          |
                                     SSH brute-force alert (webhook)
                                                          v
                      Shuffle (cloud) --> ML scoring service (FastAPI) --> analyst approval --> simulated block
```

See [`docs/architecture.md`](docs/architecture.md). The block is **simulated on purpose**: the attack source and the lab gateway share one address (172.30.0.1), so a real block would cut the victim network.

## Repository layout

| Path | Content |
|---|---|
| `lab/` | Victim container and health check |
| `attacks/` | Attack playbook, attack runner, benign-traffic generator |
| `data/` | Collection log, labeled sessions, feature building, training and evaluation scripts |
| `service/` | FastAPI scoring service, trained model, metadata |
| `shuffle/` | Masked export of the Shuffle workflow, compose file |
| `grc/27001/` | Scope and context, risk register, partial SoA, incident response procedure, internal audit checklist |
| `grc/42001/` | AI policy and roles, AI risk and impact assessment, model card, monitoring plan |
| `grc/integration/` | Traceability matrix, integration notes and audit findings |
| `evidence/` | Screenshots named by matrix row (secrets masked) |
| `docs/` | Scope, research design, architecture, decision log, evaluation report |

## Reproduce

```bash
git clone <this repo> && cd governed-ai-soc
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp evidence/.env.example .env            # set your own values; never commit .env
```

The pipeline scripts are in `data/`: `build_features.py` (session features), `train_models.py` (training) and `evaluate_day5.py` (the comparison in the table above, seed 42). Each script documents its inputs at the top. The data files it reads and writes are in `data/`, with the collection log in `data/collection_log_clean.csv`.

The scoring service is the FastAPI app in `service/app.py`. It refuses to start unless the `SOC_API_KEY` environment variable is set, and it requires that key (`x-api-key` header) on `/score`. Run it with `uvicorn` after exporting the variable.

Attacks are scripted in [`attacks/playbook.md`](attacks/playbook.md) and `attacks/run_attack.sh`. Run them only against your own lab hosts.

## SOAR workflow

Splunk alert (cron every 5 minutes, throttled 10 minutes per source IP) calls a Shuffle webhook. Shuffle sends the session to the scoring service, asks an analyst for approval by e-mail, and runs a **simulated** block. The exported workflow is in `shuffle/` with every secret masked.

## GRC documents

- **ISO 27001, scoped to the lab:** controls 8.15, 8.16, 8.20, 8.22, 8.5, 5.24-5.28 (8.8 and 8.29 optional), risks R-01 to R-09, status per control in the SoA.
- **ISO 42001, scoped to the model:** AI policy, AI risk and impact assessment (AI-01 to AI-05), model card, monitoring plan.
- The traceability matrix is [`grc/integration/traceability_matrix.csv`](grc/integration/traceability_matrix.csv). Integration notes and audit findings are in [`grc/integration/day9_integration.md`](grc/integration/day9_integration.md).

## Known limitations

- **Small, synthetic, single-lab data.** 32 sessions, generated with Nmap, Hydra and curl against one victim container. Perfect scores describe this lab only.
- **Benign traffic is narrow.** One scripted generator (web requests, one successful and one failed login, one FTP check). It has no SSH, no bursts and no multi-failure benign patterns. The 0% FPR reflects this generator, and the model may use protocol presence (for example SSH) as a shortcut.
- **Cross-validation is stratified by class, not grouped by run.** Sessions from the same run can appear in training and test folds, so the metrics in the table may be inflated.
- **"Suricata detects" means the four local rules**, not Suricata in general.
- **In the exported workflow, the scoring request body is a fixed recorded session** with no reference to the alert fields, and the decision field written by the simulated block is hard-coded as "approve". Human approval is a real step, but the logged decision is not read from the approval response.
- **No external threat-intelligence enrichment.** AbuseIPDB and VirusTotal are not part of this version, and private lab addresses would return nothing useful.
- **TLS verification is disabled** on the call to the scoring service (lab tunnel).
- **Shuffle runs in its cloud**, so session data and one e-mail address leave the lab network. The attack network itself is isolated.
- **Single operator.** No independent review or segregation of duties.
- **Not production-ready.** Not certified, not audited by a third party.

## Ethics

All attacks are run only against lab hosts that I own. The attack network (`br-victims`, 172.30.0.0/24) is isolated from third-party systems. The management components (Splunk, Shuffle, the scoring service) have limited outside connections, listed in `grc/27001/scope_context.md`. Victim credentials in `lab/victim/dockerfile` are intentionally weak, for Hydra targets only.

## Author

Hosni Nheri, telecommunications engineering student, ENET'Com Sfax.
