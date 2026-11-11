# Internal Audit Checklist — Governed AI-Assisted SOC (lab scope)

**Status:** draft for review.
**Standard:** ISO/IEC 27001:2022 clauses 9.2 (internal audit) and Annex A controls selected in `soa_partial.md`. Implemented on a defined scope, not certified.
**Audit date / auditor:** **[to fill]**
**Independence limitation:** the lab owner (Hosni Nheri, the only contributor) audits their own work. A real internal audit requires an independent auditor. State this in the gap analysis; if a supervisor can review, record their name here.

**How to use:** for each row, open the evidence, then mark **C** (conforms: evidence exists and matches the claim), **P** (partial), **N** (not conforming or evidence missing), **NA**. A row without a file path or log reference in the Evidence column cannot be marked C.

## A. Scope, risk and SoA (clauses 4 to 6)

| # | Check | Evidence to open | Result | Notes |
|---|---|---|---|---|
| A1 | Scope and context document exists: lab boundary, assets, interested parties (Day 7 requires it) | `grc/27001/scope_context.md` **[create if missing]** | | |
| A2 | Every risk R-01 to R-09 has likelihood, impact, level, owner, treatment and at least one evidence item | `risk_register.md` | | |
| A3 | Risk ratings are consistent with measured results | Day 5 report vs register | | See finding F1 |
| A4 | Every SoA control has status, justification and an existing evidence file | `soa_partial.md`, `evidence/` | | See finding F2 |
| A5 | SoA states that omitted controls are out of scope by choice, not claimed as covered | `soa_partial.md` | | |
| A6 | Wording: no document says "certified" or "compliant" | search `grc/` and the write-up | | |

## B. Controls

| # | Control | Check | Evidence to open | Result | Notes |
|---|---|---|---|---|---|
| B1 | 8.15 | Suricata `eve.json` reaches Splunk and `latest(_time)` is recent | Splunk search screenshot | | |
| B2 | 8.15 | **Auth logs** from `victim1` reach Splunk (Day 2 follow-up, needed for the SSH alert) | Splunk search on the auth sourcetype | | |
| B3 | 8.15 | Retention settings recorded | Splunk index settings | | |
| B4 | 8.16 | SSH alert configuration matches the SoA (cron `*/5 * * * *`, last 5 min, throttle 10 min on `src_ip`) and the failure threshold is documented | saved search export | | |
| B5 | 8.16 | Detection metrics exist for each attack scenario, not only SSH | Day 5 per-scenario table | | See finding F3 |
| B6 | 8.20 | Architecture diagram matches the real topology (`br-victims`, victim, sensors, Shuffle shown as a cloud service outside the boundary). `correlation-engine` is out of scope and must not appear | diagram vs `docker network ls` and `docker ps` | | |
| B7 | 8.20 | Exposed ports and outside connections are listed and justified (Splunk :8000, webhook to Shuffle cloud, tunnel to the scoring service) | playbook, Shuffle config, tunnel config | | |
| B8 | 8.22 | Segregation claim is accurate: sensors run in host network mode, so they are not isolated from the host | Suricata run command | | Expect P |
| B9 | 8.5 | Brute-force scenarios documented and detected for SSH, FTP, HTTP | playbook, collection log | | |
| B10 | 8.5 | No default or documented credentials remain in the repository (the playbook shows the Splunk password and the stand-in login password) | grep the repo | | See finding F4 |
| B11 | 5.24 | IR procedure exists, is versioned, and was followed once end to end (section 7 test record) | `incident_response_procedure.md` | | |
| B12 | 5.25 | Decision criteria are written and one decision record exists per tested alert | decision records | | |
| B13 | 5.26 | Approve and decline paths each captured | `R-03_approval_continue.png`, `R-03_decline_aborted.png` | | |
| B14 | 5.26 | Block is explicitly stated as simulated everywhere it is mentioned | all docs | | |
| B15 | 5.27 | At least one lesson recorded after a test session | review notes | | |
| B16 | 5.28 | Evidence files are named by matrix row, indexed in `evidence/README`, and masked (webhook, tunnel, keys, private addresses) | open each file | | |
| B17 | 8.8 | Nmap findings on `victim1` documented, with remediation or acceptance | Nmap output | | optional |
| B18 | 8.29 | Playbook commands match the collection log and are reproducible from a clean state | `attacks/playbook.md`, `data/collection_log_clean.csv` | | optional |
| B19 | 5.19 to 5.23 | Cloud and supplier use is recorded: Shuffle cloud, ngrok, AbuseIPDB, VirusTotal are listed with the data sent to each; the tunnel endpoint requires authentication and is closed after tests | `scope_context.md` section 3.3, FastAPI config, tunnel config | | See finding F8 |

## C. AI-related cross-checks (prepares Day 8)

| # | Check | Evidence to open | Result | Notes |
|---|---|---|---|---|
| C1 | Numbers in the register, SoA and model card equal the Day 5 table (recall 0.583 / 1.000 / 1.000, FPR 0.000, 24 attack and 8 benign sessions) | Day 5 summary CSV | | |
| C2 | Evaluation uses different runs for training and testing, or the report states that it does not | `evaluate_day5.py`, report | | See finding F5 |
| C3 | Limits stated: small, synthetic, single-lab data; local rules only; the `ET INFO` banner noise is an artifact of the stand-in server | Day 5 report, model card | | |
| C4 | Model threshold (0.7) has a recorded origin | notebook or service config | | |

## D. Findings from the desk review of the documents provided

These come from reading `soa_partial.md`, `risk_register.md`, the Day 5 report and the playbook, not from the repository. Confirm each against the repository before recording it as a finding.

| ID | Finding | Why it matters | Suggested action |
|---|---|---|---|
| F1 | **R-02 contradicts Day 5.** The register says the slow scan "evades both rules and model" with existing control "Model only" and likelihood High. Day 5 shows Suricata missed the slow cases (1 slow Nmap scan, 9 low-parallelism brute-force sessions) and the model caught all 10. | The register states the opposite of the evidence. The slow-scan result rests on **one** session. | Rewrite R-02: residual gap in Suricata alone, model caught 1 of 1 slow scan and 9 of 9 low-parallelism brute-force sessions, small sample, a burst-then-quiet attack could evade both. Re-rate with that. |
| F2 | **5.24 is marked Implemented, but the IR procedure did not exist** when the SoA was written. 5.28 and 8.16 also rest on statuses estimated, not verified. | Overclaiming; the first thing an examiner checks. | Keep 5.24 Partial until section 7 of the IR procedure has been run once. Verify the evidence file for every Implemented row. |
| F3 | 8.16 evidence is an SSH alert only. Scan, FTP and HTTP detections have metrics but no Splunk alert. | The control description ("alerts on scans and brute force") overstates what is automated. | Say "alert for SSH; detection-only for others", or add alerts. |
| F4 | The playbook shows `SPLUNK_PASSWORD='[REDACTED]'` and the login-server password in clear text. | Credentials in a public repo, and weak authentication evidence for 8.5. | Remove from the playbook, use an environment file excluded from Git, rotate. |
| F5 | The Day 5 evaluation uses `StratifiedKFold(shuffle=True)` on 32 sessions from two capture windows on one day (per the previous review of the script). Sessions from the same run can sit in both train and test. | The roadmap requires a split by session and a different-session test; 100% recall and 0% FPR may be inflated. | Use `GroupKFold` on a run identifier, or keep sessions from a separate capture as test, and report the change. |
| F6 | `risk_register.md` mentions "the Avenloft risk register". If this is a client name, it must not appear in a public repo. | Client confidentiality. | Replace with "a previous engagement" or remove. |
| F7 | Single person (Hosni Nheri) holds every role, confirmed by the owner. The same person approves the simulated block and owns the system. | No independent review or segregation of duties. | State it in the gap analysis. Keep the Shuffle decision log and the decision records as compensating measures. |
| F8 | The Shuffle workflow runs in the **cloud**. Alert content leaves the lab, the scoring service is reached from the Internet through a tunnel, and API keys are stored at the provider. The earlier statement of an isolated lab with no outside route was inaccurate. | Supplier and exposure risk not yet in the register; a weak Splunk password and an unauthenticated tunnel would make it worse. | Add a risk for the tunnel exposure and SaaS dependence (R-09), require a token on FastAPI, rotate the Splunk password, and correct the scope wording in the final report. |

## E. Result summary (fill after the audit)

| Section | Rows | C | P | N | NA |
|---|---|---|---|---|---|
| A | 6 | | | | |
| B | 19 | | | | |
| C | 4 | | | | |

Corrective actions (owner, date, status): **[to fill]**. Re-audit date: **[to fill]**.
