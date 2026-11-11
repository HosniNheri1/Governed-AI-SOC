# AI Risk Assessment and AI System Impact Assessment

Document: grc/42001/02-ai-risk-and-impact-assessment.md | Version 0.1 | 2026-11-11 | Status: Draft
Related ISO/IEC 42001 topics: AI risk assessment (6.1.2), AI risk treatment (6.1.3), AI system impact assessment (6.1.4); Annex A theme on assessing impacts of AI systems.
Risk IDs R-01 to R-07 follow the traceability matrix in the roadmap. AI-01 onward are new. Align them with the ISO 27001 register in `grc/27001/` before publishing.

## 1. Method

Likelihood (L) and impact (I) are rated 1 to 5 by the system owner, score = L x I, in the style of the NIST 800-30 register. Ratings are judgment calls and are marked as initial. Each risk cites the measurement or log that motivates it. A risk with no measurement is marked **unmeasured**, which is different from low.

Statistical note. With 8 benign sessions, 0 false positives gives a one-sided 95% upper bound on FPR of 1 - 0.05^(1/8) = 31.2%. With 24 attack sessions, 24 detected gives a one-sided 95% lower bound on recall of 0.05^(1/24) = 88.3%. The Day 5 data cannot rule out an FPR near 30%.

## 2. Evidence base

| Item | Value | Source |
|---|---|---|
| Sessions | 32 (24 attack, 8 benign), collected 2026-11-07, 10:43 to 13:11 VM time (UTC-5) | `day5_evaluation_results.csv` |
| Class counts | benign 8, ssh 7, nmap_syn_scan 6, ftp 6, http 5 | same |
| Suricata alone | P 1.00, R 0.583, F1 0.737, FPR 0, TP 14, FP 0, FN 10, TN 8 | `day5_evaluation_summary.csv` |
| Model alone (RF, out-of-fold) | P 1.00, R 1.00, F1 1.00, FPR 0, TP 24, FP 0, FN 0, TN 8 | same |
| Hybrid OR | identical to model alone | same |
| Suricata recall by class | ftp 3/6, http 3/5, nmap 5/6, ssh 3/7 | computed from results CSV |
| Multiclass model result | accuracy 31/32 = 0.969; one nmap_syn_scan session predicted as http_bruteforce | computed from results CSV |
| Suricata baseline definition | alerts from 4 local rules only, SIDs 9000001 to 9000004 | `evaluate_day5.py` |
| Webhook delivery | Splunk to Shuffle returned HTTP 200 for the 13:30 UTC run | Splunk `sendmodalert` log, evidence/ |
| Decline test | run of 2026-11-09, ABORTED after 5 min 10 s, reason not kept in Shuffle logs | evidence/R-03_decline_aborted.png |
| Ingestion stoppage | latest event 2026-11-08 16:49:16 seen on 2026-11-11 | Splunk `stats latest(_time)` |

## 3. AI risk register

| ID | Risk | Driver and evidence | L | I | Score | Treatment | Status |
|---|---|---|---|---|---|---|---|
| R-01 | Nmap SYN scan missed or mislabeled | Suricata flagged 5/6; model flagged 6/6 but 1 session was labeled http_bruteforce | 2 | 3 | 6 | Hybrid OR keeps both detectors; track multiclass confusion | Open |
| R-02 | Slow scan evades Suricata's fixed-rate threshold | **Measured on one session.** Suricata missed the single slow Nmap scan (`-T2`, 500 ports, 202s) in the Day 5 dataset; the model correctly flagged it as an attack and labeled it `nmap_syn_scan`. Sample size is 1, so this result does not establish a general detection rate for slow scans | 2 | 3 | 6 | Collect more slow-scan sessions with varied timing before citing a recall figure; keep as a measured result with a stated small-sample caveat, not as unmeasured | Open |
| R-03 | SSH brute force missed by rules; oversight record weak | Suricata flagged 3/7; model 7/7. Decision record is static (see G-1) | 3 | 4 | 12 | Capture real decision in the log; keep hybrid OR | Open |
| R-04 | FTP and HTTP brute force missed; auth log quality | Suricata ftp 3/6, http 3/5; model 11/11 | 3 | 3 | 9 | Check auth-log field completeness; per-class monitoring | Open |
| R-05 | False positive leads to a wrongful block | FPR 0/8, but upper bound 31.2%. Block is simulated and needs approval | 2 | 4 | 8 | Approval step; FPR monitoring; do not enable real blocking | Open |
| R-06 | Model drift | Training data from one day. No drift measurement yet | 3 | 3 | 9 | Monitoring plan indicators and thresholds | Open |
| R-07 | Adversarial evasion (low-rate, timing changes, padding) | Features are counts and timings an attacker controls. Not tested | 2 | 4 | 8 | Documented risk only. Out of scope for experiments | Accepted |
| AI-01 | Optimistic evaluation | Recall 1.00 is a warning sign per the research design. One row per session (design said 60 s window); stratified 5-fold out-of-fold, not a reserved test set; protocol-specific counters (`n_ftp_events`, `n_ssh_events`, `n_http_post`) may reveal the class | 4 | 4 | 16 | Reserve test-only sessions; run a different-session test; ablate protocol counters; document the deviation from the design | Open |
| AI-02 | Human oversight not provable | `simulated-block` hard-codes `"decision":"approve"` and an analyst address. A rejection ends the run as ABORTED with no recorded reason | 4 | 4 | 16 | Write the actual approval result and reason into the record; log rejections explicitly | Open (G-1) |
| R-09 | Endpoint exposure and secrets | The scoring endpoint is reached through a public tunnel URL with an API key header. TLS verification is off on the HTTP node. The Shuffle export contains an API key and a password in clear text | 4 | 4 | 16 | Rotate the credentials, mask the export, restrict or remove the tunnel, turn TLS verification on | Open (G-2) |
| AI-03 | Baseline is weak, so the gain is overstated | "Suricata alone" means 4 local rules. A tuned ruleset may close the gap | 3 | 3 | 9 | State the baseline definition next to every number; optionally add a tuned-ruleset run | Open |
| AI-04 | Dataset bias and representativeness | One day, one lab, attacks scripted by the author, default tool parameters, class imbalance (8/7/6/6/5) | 4 | 3 | 12 | Vary tools, timing and targets; state limits; no production claims | Open |
| AI-05 | Third-party components | scikit-learn, Splunk, Shuffle, Suricata, tunnel service. AbuseIPDB and VirusTotal are in the roadmap but not in the workflow export | 2 | 3 | 6 | Pin versions in a requirements file; list suppliers; add enrichment or remove it from claims | Open |
| R-08 | Silent loss of telemetry | Ingestion was 3 days stale on 2026-11-11 because the capture chain had stopped between sessions | 4 | 3 | 12 | Ingestion-freshness alert; restart checklist | Open |

Highest scores (16): AI-01, AI-02, R-09. These three (not a contiguous ID range) come first in the treatment plan.

## 4. AI system impact assessment

### 4.1 System and context
Advisory scoring of network sessions in a lab. Output feeds an analyst, who decides on a simulated block. No real users, no production traffic.

### 4.2 Interested parties and potential impacts

| Party | Potential impact | Severity in the lab | Severity if deployed in production |
|---|---|---|---|
| SOC analyst | Over-reliance on the score (automation bias); alert fatigue if false positives rise | Low | Medium |
| Users or hosts behind a flagged IP | Wrongful block of a legitimate source after a false positive | None (simulated) | High |
| System or asset owner | Undetected intrusion after a false negative (low-rate brute force; the single slow-scan session observed was caught, see R-02) | None | High |
| Individuals whose IP addresses are processed | IP addresses can be personal data in some jurisdictions | None (RFC 1918 lab addresses) | Medium |
| Readers of the portfolio | Misleading conclusions if limits are not stated | Medium | n/a |

### 4.3 Impact analysis by theme

- **False negatives.** Suricata missed 10 of 24 attack sessions, all caught by the model. The reverse case (model misses, Suricata catches) did not occur in Day 5. This includes the one slow-scan session and nine low-parallelism brute-force sessions (R-02) - all missed by Suricata's fixed-rate thresholds and caught by the model, though the slow-scan result rests on a single session and should not be read as a general detection rate.
- **False positives.** None observed on 8 benign sessions. The bound of 31.2% means a real rate could be far higher. The approval step limits harm, and the block is simulated.
- **Fairness and bias.** The feature set contains no IP addresses or user identifiers (20 numeric features, see the model card). The main bias is dataset coverage: one lab, authored attacks, small classes.
- **Transparency.** The score and label are passed to the analyst. Explanations (feature importance) are not yet provided to the analyst.
- **Privacy.** Events contain source and destination IPs and ports. Lab addresses only. No payload content is used as a feature.
- **Safety of the response.** No real action is taken. Any move to real blocking requires a new impact assessment.

### 4.4 Conclusion
Acceptable for lab use with human approval and simulated response. Not acceptable for production decisions on current evidence.

## 5. Treatment plan

| Gap | Action | Owner | Status |
|---|---|---|---|
| G-1 | Pass the Analyst-approval result and reason into the record instead of a fixed value; keep a rejected-decision log | System owner | To do |
| G-2 | Rotate the exposed API key and password; mask them in the export; remove the public tunnel after tests; enable TLS verification | System owner | To do, before any commit of the export |
| G-3 | Reserve test-only sessions and repeat evaluation; add per-class report and Hybrid AND to the script; document the per-session unit as a deviation from the research design | Model validator | To do |
| G-4 | Collect slow-scan and low-and-slow brute-force sessions | Data steward | To do |
| G-5 | Record model version and file hash, pin dependencies, store the training data checksum | System owner | To do |
| G-6 | Add ingestion-freshness alert and a restart checklist | System owner | To do |

## 6. Residual risk statement
After treatment, risks AI-01, AI-02 and R-09 should fall to 8 or below. R-02 stays open for a larger slow-scan sample; the single-session result above is kept as a measured (not unmeasured) finding with its small-sample caveat stated. The owner accepts R-07 as a documented risk.
