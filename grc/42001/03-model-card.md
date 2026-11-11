# Model Card: Session Scorer (Random Forest)

Document: grc/42001/03-model-card.md | Version 0.1 | 2026-11-11 | Status: Draft
Related ISO/IEC 42001 topics: information for interested parties, AI system life cycle, data for AI systems.

## 1. Model details

| Field | Value |
|---|---|
| Name | session-scorer |
| Type | Random Forest classifier (scikit-learn), 200 trees, `class_weight="balanced"`, `random_state=42` |
| Task | Classify one source-IP session as benign, nmap_syn_scan, ssh_bruteforce, ftp_bruteforce or http_bruteforce |
| Output | Label and score, returned by the FastAPI `/score` endpoint; the workflow also reads an `alert` boolean |
| Owner | Hosni Nheri |
| Model version and file hash | **To record (gap G-5).** Not captured yet |
| Dependencies | **To pin** in `requirements.txt` |

## 2. Intended use

Advisory ranking of Suricata-derived sessions inside an isolated lab, to help an analyst decide on a simulated block. Used together with Suricata, never as a replacement.

Out of scope: production traffic, automatic blocking, other attack types (version-detection scans, DDoS, malware, web exploits), networks that differ from the lab. One slow Nmap scan (`-T2`) is in the training data (see limitation 7 below for its sample size).

## 3. Data

| Item | Value |
|---|---|
| Source | Suricata `eve.json` events ingested in Splunk, exported to `day4_labeled_fixed.csv` |
| Collection | Scripted attacks and benign traffic by the author, 2026-11-07 |
| Unit | One record per `session_id` (design document specified 60 s windows; see limitation 4) |
| Size | 32 sessions: benign 8, ssh_bruteforce 7, nmap_syn_scan 6, ftp_bruteforce 6, http_bruteforce 5 |
| Labels | From the author's attack run log, by timestamp and source IP |
| Provenance | `data/collection_log.csv` (date, scenario, command, duration, session ID) |
| Personal data | None. Lab IPs only |

## 4. Features (20, from `day4_features_fixed.csv`)

Volume and timing: `n_events`, `duration_sec`, `events_per_sec`, `mean_interarrival_sec`, `std_interarrival_sec`.
Flow: `n_unique_victim_ports`, `n_flow_events`, `bytes_toserver`, `bytes_toclient`, `pkts_toserver`, `pkts_toclient`.
TCP flags: `tcp_syn_count`, `tcp_rst_count`, `tcp_fin_count`, `tcp_ack_count`.
Protocol: `n_ftp_events`, `n_http_events`, `n_ssh_events`, `ftp_fail_rate`, `n_http_post`.

No IP address or user identifier is a feature. Missing values are filled with 0.

## 5. Evaluation

Protocol: 5-fold stratified cross-validation by session, seed 42, out-of-fold predictions, one prediction per session. Suricata baseline: an alert from any of 4 local rules (SIDs 9000001 to 9000004) in the session. Hybrid: Suricata OR model.

### 5.1 Binary detection (attack vs benign)

| System | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Suricata alone | 1.000 | 0.583 | 0.737 | 0.000 | 14 | 0 | 10 | 8 |
| Model alone (out-of-fold) | 1.000 | 1.000 | 1.000 | 0.000 | 24 | 0 | 0 | 8 |
| Hybrid OR | 1.000 | 1.000 | 1.000 | 0.000 | 24 | 0 | 0 | 8 |

Hybrid AND was not computed by the script. From the results table it equals Suricata alone, because the model flagged every attack session.

Uncertainty: one-sided 95% bounds are recall at least 0.883 (24/24) and FPR at most 0.312 (0/8).

### 5.2 Per-class results

| Class | Sessions | Suricata recall | Model precision | Model recall | Model F1 |
|---|---|---|---|---|---|
| benign | 8 | n/a | 1.000 | 1.000 | 1.000 |
| ftp_bruteforce | 6 | 3/6 = 0.500 | 1.000 | 1.000 | 1.000 |
| http_bruteforce | 5 | 3/5 = 0.600 | 0.833 | 1.000 | 0.909 |
| nmap_syn_scan | 6 | 5/6 = 0.833 | 1.000 | 0.833 | 0.909 |
| ssh_bruteforce | 7 | 3/7 = 0.429 | 1.000 | 1.000 | 1.000 |

Multiclass accuracy: 31/32 = 0.969. The single error is an nmap_syn_scan session predicted as http_bruteforce. It still counts as an attack in the binary table.

Rows come from `day5_evaluation_results.csv`. The script prints only the binary table; per-class values were computed from the CSV and should be added to the script (gap G-3).

## 6. Limitations

1. Small, synthetic, single-lab data collected on one day. Results do not transfer directly to production.
2. Labels come from the author's own scripts.
3. Perfect binary recall on 24 sessions is a warning sign, not a result. The protocol counters `n_ftp_events`, `n_ssh_events` and `n_http_post` may reveal the attack type directly. An ablation has not been run.
4. The unit is the session, not the 60 s window fixed in the research design. This deviation is documented here and in the risk assessment (R-08).
5. The evaluation uses cross-validation, not a reserved test set with at least one session of each type held out.
6. The baseline is 4 local rules, not a tuned ruleset. The gain over Suricata is a gain over these rules.
7. One slow-scan session (`-T2`, 500 ports) is in the evaluation set and was correctly caught and labeled by the model, while Suricata missed it (R-02) - but this is a single session, not a general detection rate for slow scans. No version-detection scan beyond the one `nmap -sV` session (see failure mode table below) is in the set. Isolation Forest was not evaluated here.
8. The Shuffle test run posts a fixed session payload (a Day 5 session). It shows the pipeline works, but it is not an independent performance test.

## 7. Known failure modes

| Failure | Observed | Consequence |
|---|---|---|
| Scan labeled as HTTP brute force | Yes, 1 of 6 nmap sessions | Wrong class in the alert; still flagged as an attack |
| Attack classes not seen in training (other tools, other timing profiles than the single slow-scan sample) | Not tested | Probable miss; Suricata may also miss |
| Input drift (different timing, volume, tools) | Not tested | Unknown score quality |
| Telemetry gap (Suricata or login server stopped) | Yes, 3 days stale on 2026-11-11 | No sessions to score, silent failure |
| False positive on unusual benign traffic | Not observed on 8 sessions; bound 31.2% | Wrongful block if approval is skipped |

## 8. Human oversight and deployment

Splunk alert, then webhook `splunk-alert-intake`, then `ml-score-session` (condition: `alert` equals true), then the `Analyst-approval` user-input step, then `simulated-block`. Webhook delivery returned HTTP 200 on the 13:30 UTC run. A refusal test on 2026-11-09 ended ABORTED after 5 min 10 s; the reason was not retained (gap G-1). The workflow has no VirusTotal or AbuseIPDB step in the current export.

## 9. Change log

| Date | Version | Change |
|---|---|---|
| 2026-11-11 | 0.1 | First version, from Day 5 results and the Day 6 workflow export |
