# Research Design (fixed before seeing results)

Version 0.1 | Day 1

## Question
Does an ML detector add value over Suricata rules alone for detecting scans and brute force in a small network, and how can it be governed?

## Hypothesis
H1: a hybrid (rules + ML) misses fewer attacks, or raises fewer false alarms, than rules alone on held-out sessions.
H0: the hybrid shows no measurable improvement over rules alone.
Either outcome is reportable.

## Unit of analysis
One record = one source IP in one fixed time window (proposed: 60 seconds). Label = attack class active from that IP in that window, or benign. Decide the window size now and do not change it after seeing results.

## Classes
benign, port_scan, ssh_bruteforce, ftp_bruteforce, http_bruteforce.
Slow scans are a sub-type of port_scan kept as a tag for gap analysis.

## Labeling rule
Label by timestamp window and source IP from the attack run log (data/collection_log.csv). Every run has a session_id.

## Split rule
Split by session_id, never randomly. All windows from one session stay in the same split. Fix the random seed. Reserve at least one attack session of each type for the test set only.

## Compared systems
1. Suricata alone (an alert from any relevant rule in the window = positive).
2. ML model alone (baseline: Random Forest or XGBoost; optional: Isolation Forest).
3. Hybrid OR: positive if Suricata or ML flags it.
4. Hybrid AND: positive only if both flag it (precision check).

## Metrics
Per class: precision, recall, F1. Overall: false positive rate (FPR) on benign windows, confusion matrix. Report counts as well as percentages because the dataset is small.
Optional: detection delay from attack start to first alert.

## Proposed decision rule (adjust now, not later)
The hybrid is considered useful if it improves recall on at least one attack class over Suricata alone and keeps FPR within 1 percentage point of Suricata alone, on held-out sessions.

## Threats to validity (record now, expand later)
- Small, synthetic, single-lab dataset.
- Labels derived from my own attack scripts.
- Suricata ruleset version and tuning affect the baseline.
- Near-perfect scores are a warning sign, not a result.
- Possible leakage through IP addresses or timing features: check feature list.

## Optional generalization test
Train on lab data, test on a different session type or a public dataset (CIC-IDS2017 or UNSW-NB15), and report the drop. CIC-IDS2017 has documented labeling and artifact issues, so do not rely on it alone.
