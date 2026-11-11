# Monitoring Plan

Document: grc/42001/04-monitoring-plan.md | Version 0.1 | 2026-11-11 | Status: Draft
Related ISO/IEC 42001 topics: monitoring and measurement (9.1), AI system life cycle, use of AI systems.
All thresholds below are **proposals from the system owner**. They are derived from 32 sessions and should be revisited once more data exists.

## 1. Indicators and thresholds

| # | Indicator | Definition | Day 5 baseline | Warning threshold | Action |
|---|---|---|---|---|---|
| M1 | Ingestion freshness | `now() - latest(_time)` for `sourcetype="suricata:eve"` | Failure seen 2026-11-11: about 3 days of lag | Lag above 15 min | Run the restart checklist (section 4) |
| M2 | Recall on replayed attacks | Replay each playbook scenario; share scored as attack | 24/24 (lower bound 0.883) | Any replayed attack scored benign | Investigate; consider retraining |
| M3 | False-positive rate | Rejected alerts divided by scored alerts, per review window; benign replay FPR | 0/8 | 2 or more confirmed false positives per window, or reject rate of 10% or more over at least 20 alerts | Review threshold and data; retraining review |
| M4 | Rule/model disagreement | Share of sessions flagged by the model only | 10/32 = 31% (all 10 were attack sessions) | Shift of more than 15 points | Check rules, features, traffic mix |
| M5 | Feature drift | Population stability index per feature versus the training set | Not yet measured | PSI above 0.2 on 3 or more features | Retraining review |
| M6 | Class mix of alerts | Count of predicted labels per window | benign 8, ssh 7, nmap 6, ftp 6, http 5 (training mix) | Unexpected class dominates or new pattern | Review for new attack types |
| M7 | Decision-record completeness | Block actions with approve/reject, timestamp, analyst, reason | Incomplete: decision is a fixed value (gap G-1) | Below 100% | Fix workflow; treat as a finding |
| M8 | Approval latency and abandonment | Time to decision; runs ABORTED | One run ABORTED after 5 min 10 s | Any alert ABORTED without a logged reason | Review timeout and reminders |
| M9 | Endpoint and secret hygiene | Credentials rotated, export masked, endpoint reachable only as intended | Open (risk R-09) | Any clear-text secret in a repository file | Rotate immediately |

M5 caveat: PSI on 32 training sessions is unstable. Use 5 quantile bins and treat the value as a hint, not a verdict, until more sessions are collected.

## 2. Measurement sources

| Indicator | Source | Status |
|---|---|---|
| M1 | Splunk search below | Available |
| M2, M6 | Playbook replay, `/score` responses | To script |
| M3, M7, M8 | Shuffle execution log and decision record | Needs the decision written to Splunk or a file (G-1) |
| M4, M5 | Offline script over exported sessions | To script |
| M9 | Repository scan and manual check | To do |

Freshness search:

```
index=main sourcetype="suricata:eve"
| stats latest(_time) as latest
| eval lag_min=round((now()-latest)/60,1)
```

## 3. Review cadence

| Cadence | Activity |
|---|---|
| Per lab session | M1 check before starting; restart checklist if stale |
| Weekly while the lab is active | Replay M2 and benign set; review M3, M7, M8 |
| Monthly | Review M4, M5, M6; update this plan and the model card |
| After any incident or model change | Update the model card failure modes and risk register |

## 4. Restart checklist (from the observed 2026-11-11 incident)

1. `docker ps -a | grep -E "suricata-internal|victim1"`; start any container that is Exited.
2. `docker exec suricata-internal suricatasc -c ruleset-stats`.
3. Check the login server inside `victim1` (port 8080) and restart it if absent.
4. Re-run the freshness search and confirm a recent event before testing the alert.

## 5. Retraining triggers and procedure

Triggers (any one): M2 fails; M3 threshold crossed; M5 breached on 3 or more features; a new attack scenario is added to the playbook; a change of Suricata ruleset.

Procedure:
1. Add new labeled sessions to the collection log, with `session_id`.
2. Reserve test-only sessions (at least one per attack type) and fix the seed.
3. Retrain, then re-run Suricata alone, model alone, hybrid OR and hybrid AND, with per-class metrics and confidence bounds.
4. Compare with the table in the model card; investigate any gain or loss above 5 points.
5. Update the model card, record the model version and file hash.
6. The retraining approver signs off in the change log. No deployment without that line.

## 6. Escalation and records

Every threshold breach is written in the log below with date, indicator, value, decision and owner.

| Date | Indicator | Value | Decision | Owner |
|---|---|---|---|---|
| 2026-11-11 | M1 | About 3 days stale (latest event 2026-11-08 16:49:16) | Restart capture chain; add freshness alert | Hosni Nheri |
