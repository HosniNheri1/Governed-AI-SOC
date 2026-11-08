# Day 5 — Evaluation Report

**Research question:** Does an ML detector add value over Suricata rules alone for detecting scans and brute force in a small network, and how can it be governed?

**Hypothesis (Day 1):** A hybrid (rules + ML) reduces missed detections or false positives compared with rules alone.

**Dataset:** 32 sessions (8 benign, 6 nmap_syn_scan, 7 ssh_bruteforce, 6 ftp_bruteforce, 5 http_bruteforce), collected across two capture windows on 2026-11-07. Evaluation is session-based: every number below is counted in units of whole attack/benign sessions, never individual packets or alerts, so no session's traffic appears in both a detector's "seen" and "unseen" data at once.

## 1. Summary table

| Detector | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Suricata alone | 1.000 | 0.583 | 0.737 | 0.000 | 14 | 0 | 10 | 8 |
| Model alone (Random Forest, out-of-fold) | 1.000 | 1.000 | 1.000 | 0.000 | 24 | 0 | 0 | 8 |
| Hybrid (Suricata OR model) | 1.000 | 1.000 | 1.000 | 0.000 | 24 | 0 | 0 | 8 |

**Model**: Random Forest (200 trees, `class_weight="balanced"`), 20 features aggregated per session from raw Suricata flow/protocol events — ports, byte/packet counts, TCP flags, inter-arrival timing, FTP reply codes, HTTP method counts. Suricata's own alert fields were deliberately excluded from the feature set so the model's score is independent of the rule-based detector it is being compared against. Evaluated with 5-fold stratified cross-validation (seed 42); the Recall/Precision/F1 above pool the out-of-fold predictions across all 32 sessions, so every session is scored only by a model that never saw it during training.

**Suricata**: evaluated exactly as shipped in Day 2 — a session counts as "detected" if any of the four local signatures (9000001–9000004) fired during its time window. No retroactive threshold tuning.

## 2. Headline finding: Suricata misses low-and-slow brute force and a slow scan — the model catches both

Suricata's recall of 58.3% means it missed 10 of 24 attack sessions. Cross-referencing the 10 missed sessions against the exact Hydra/Nmap commands run (`attacks/playbook.md`, `data/collection_log_clean.csv`) shows a clean, consistent pattern with no exceptions:

| Thread count (`hydra -t`) | Sessions | Detected by Suricata |
|---|---|---|
| `-t 4` or `-t 6` | 9 | 9 / 9 |
| `-t 1` or `-t 2` | 9 | 0 / 9 |

Every brute-force session run with low parallelism (`-t1`/`-t2`) was missed; every session run with higher parallelism (`-t4`/`-t6`) was caught. The cause is mechanical, not random: the local Suricata rules (9000002–9000004) use `threshold: type both, count 5, seconds 60` — five matching events within a 60-second window. With only 1–2 parallel connections attempting 8 passwords, the connection/failure rate per unit time never reaches that threshold inside the session's short runtime, even though the full session is still a genuine brute-force attempt.

The same pattern appears in reconnaissance: the one Nmap scan run with `-T2` (Polite timing, deliberately slow, 500 ports over ~202 seconds) was also missed by Suricata — the SYN-count threshold rule (9000001: 20 SYNs in 5 seconds) never fires at that rate — while every faster scan was caught.

The Random Forest model caught every one of these 10 sessions. It does not rely on a fixed-rate threshold in a short rolling window; its features (total session duration, total distinct ports touched, total FTP failure rate, total HTTP POSTs) are computed over the **whole session**, so a slow attack that never bursts past a per-second threshold still accumulates a clearly abnormal profile by the time the session ends.

**This is the project's clearest answer to the research question.** On this lab's data, the hybrid detector does reduce missed detections relative to rules alone, and the mechanism is identifiable and explainable rather than a statistical artifact: Suricata's threshold rules have a structural blind spot for low-and-slow behavior, and the ML layer's duration/total-count features close exactly that gap. This also matches the roadmap's own expected finding (traceability matrix row R-02, "Slow scan: Model only (expected gap)").

## 3. The nmap `-sV` gap (from Day 4, re-confirmed here)

One `nmap_syn_scan` session (`-sV`, service/version detection) triggers real HTTP requests to identify the service banner on port 8080, giving it `n_http_post > 0` — a feature otherwise exclusive to HTTP brute-force sessions. In the Day 4 cross-validation this session was misclassified as `http_bruteforce` in one fold. In this Day 5 binary (attack-vs-benign) framing the misclassification doesn't cost anything, since both labels are "attack" — but it is worth carrying into the model card (Day 8) as a known limitation: **active scanning techniques that probe the application layer can resemble application-layer brute force** in a model trained only on network/protocol-level features. A production system would need a feature that distinguishes "one request per port, broad spread" (scan) from "many requests to one endpoint" (brute force) more explicitly than this feature set does.

## 4. Honest limits of this evaluation

Per the roadmap's Day 1 risk register and Section 8 wording rules, stated plainly:

- **Small, synthetic, single-lab dataset.** 32 sessions total, 5–8 per class. The model's 100% recall and precision are not claimed as a generalizable result — they describe performance on this lab's specific traffic, generated by a small number of tools (Nmap, Hydra, curl) against one victim container. A different attacker toolset, a different victim service, or real-world background noise would likely lower this score.
- **The hybrid result here is identical to the model-alone result** (both 100% recall, 0 FPR) because the model alone already caught everything Suricata caught plus everything it missed, on this dataset. This should not be read as "the model replaces Suricata" — the correct, supportable claim is narrower: on this lab's data, for these four attack types, the rule-based layer's recall is bounded by a specific, named mechanism (fixed-count threshold in a short window), and an ML layer using session-duration-scale features closed that specific gap. A different attack (e.g. one that bursts briefly and then goes quiet for the rest of the session) could plausibly evade both.
- **Zero false positives for both detectors** is a direct consequence of only having 8 benign sessions and a feature set that cleanly separates attack traffic from this lab's specific benign-traffic generator. It should not be read as "0% false positive rate in general."
- **The research question's hypothesis — "hybrid reduces missed detections or false positives compared with rules alone" — is supported for missed detections (recall 58.3% → 100%) but not independently tested for false positives**, since Suricata alone already had FPR = 0.000 on this data; there was no false-positive problem for the hybrid to improve on here.

## 5. What this means for Day 8 (ISO 42001)

This evaluation gives Day 8's AI risk assessment two concrete, evidenced items rather than generic text:
- A named false-negative mode for the rule-based layer (low-and-slow evasion of fixed-count thresholds) that the AI system is specifically introduced to mitigate — this is the system's documented intended use case.
- A named limitation of the AI layer itself (confusing active-scan application probes with brute force) that the AI risk assessment and model card should disclose, consistent with Day 8's requirement to cover "false negatives, false positives... dataset bias."

## 6. Files produced

- `data/day5_evaluation_results.csv` — per-session detection table (Suricata flag / model flag / hybrid flag / ground truth)
- `data/day5_evaluation_summary.csv` — the three-row summary table above
- `data/evaluate_day5.py` — evaluation script (reproducible, seed 42)
