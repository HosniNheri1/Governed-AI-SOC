# Statement of Applicability (partial) — Governed AI-Assisted SOC

**Status:** draft for review. Statuses revised on 2026-11-11 after a desk review of the lab documents.
**Standard:** ISO/IEC 27001:2022, Annex A. Partial SoA limited to the controls the lab exercises. Implemented on a defined scope, not certified.
**Scope:** lab (attacker VM, victim containers, Suricata sensors, Splunk, ML scoring service) plus the Shuffle workflow, which runs in the Shuffle cloud outside the lab boundary (see `scope_context.md`).
**Linked documents:** `scope_context.md`, `risk_register.md` (risk IDs), `incident_response_procedure.md`, `internal_audit_checklist.md`, traceability matrix (Day 9).

## Selected controls

| Control | Title | Applicable | Status | How the lab exercises it | Evidence | Risks |
|---|---|---|---|---|---|---|
| 8.15 | Logging | Yes | Implemented | Suricata `eve.json` and auth logs shipped to Splunk | Ingestion screenshots, `latest(_time)` check, retention settings | R-04, R-05, R-08 |
| 8.16 | Monitoring activities | Yes | Partial | Splunk alert on SSH brute force only (cron `*/5 * * * *`, last 5 minutes, throttle 10 min on `src_ip`); scans and FTP/HTTP brute force are detection-only (Suricata rules, ML scoring) with no Splunk alert | `R-03_splunk_alert_to_shuffle.png`, `R-03_splunk_webhook_log.png`, detection metrics (Day 5) | R-01, R-02, R-03, R-06 |
| 8.20 | Networks security | Yes | Partial | Attack network `br-victims` isolated from third parties; management side has outside connections (tunnel, Shuffle cloud webhook, enrichment APIs, updates) | Architecture diagram, Suricata configuration, `scope_context.md` section 3.3 | R-01, R-09 |
| 8.22 | Segregation of networks | Yes | Partial | Attacker, victim and sensor roles separated on the lab network; sensors run in host network mode, so they are not isolated from the host | Architecture diagram, Suricata run command | R-09 |
| 8.5 | Secure authentication | Yes | Partial | Exercised as an attack scenario (Hydra against SSH, FTP, HTTP) and detected; strong authentication itself is not the object of the lab; the default Splunk password is to be rotated and removed from the playbook | Hydra runs, failed-login counts | R-03, R-04, R-09 |
| 5.23 | Information security for use of cloud services | Yes | Partial | Shuffle workflow runs in the Shuffle cloud; alert content and enrichment calls leave the lab; no supplier assessment beyond terms of use | `scope_context.md` section 3.3, masked Shuffle captures | R-09 |
| 5.24 | Incident management planning and preparation | Yes | Partial | IR procedure v0.1 and SOAR workflow defined; the dry runs in section 7 of the procedure are not yet completed | `incident_response_procedure.md`, Shuffle workflow | R-03 |
| 5.25 | Assessment and decision on information security events | Yes | Partial | Decision criteria written in the IR procedure; ML score (`ssh_bruteforce`, 0.985 vs threshold 0.7) and one analyst decision captured; no decision record yet per tested alert | `R-03_fastapi_score_masque.png`, `incident_response_procedure.md` | R-03, R-05 |
| 5.26 | Response to information security incidents | Yes | Partial | Analyst approval, then simulated block (no real blocking) | `R-03_approval_continue.png`, `R-03_decline_aborted.png` | R-03 |
| 5.27 | Learning from information security incidents | Yes | Partial | Lessons recorded as lab notes and gap analysis (Day 9) | Gap analysis | R-02, R-06 |
| 5.28 | Collection of evidence | Yes | Implemented | Screenshots and logs kept by matrix row, sensitive data masked | `evidence/` and its README | R-03 |
| 8.8 | Management of technical vulnerabilities | Optional | Partial | Nmap scan findings on victims | Nmap output | R-01 |
| 8.29 | Security testing in development and acceptance | Optional | Partial | Repeatable attack playbook and run log; adversarial evasion only documented | Playbook, run log | R-07 |

## Out of scope (not covered)

All other Annex A controls are out of scope for the lab (organizational, people, physical and most technological controls), including segregation of duties (5.3): one person holds every role, which is recorded as a limitation in the gap analysis. This is a deliberate scoping choice, documented in the gap analysis, not a claim of coverage.

## Notes
- Status values: Implemented, Partial (some aspects only), Not implemented.
- Blocking is simulated: control 5.26 is therefore marked Partial.
- 5.24 moves to Implemented only after the three dry runs in section 7 of the IR procedure have been completed.
- Each selected control needs at least one concrete evidence item before the Day 7 exit criterion is met.
