# Incident Response Procedure — Governed AI-Assisted SOC (lab scope)

**Status:** draft for review.
**Standard:** ISO/IEC 27001:2022, Annex A 5.24 to 5.28. Implemented on a defined scope, not certified.
**Scope:** lab (attacker VM, victim containers, Suricata sensor(s), Splunk, ML scoring service) plus the Shuffle workflow, which runs in the Shuffle cloud and is reached through a webhook and a tunnel.
**Linked documents:** `risk_register.md` (R-01 to R-09), `soa_partial.md`, `data/collection_log_clean.csv`, `attacks/playbook.md`, `evidence/README`.
**Version / date / owner:** v0.1 / 2026-11-11 / Hosni Nheri

## 1. Purpose and limits

This procedure defines how an alert in the lab is detected, assessed, answered, recorded and reviewed.

What it covers well: SSH brute force, which has an automated Splunk → Shuffle workflow with analyst approval and a **simulated** block.

What it does not cover:
- **No automated response exists** for Nmap scans, FTP brute force or HTTP brute force (R-04). Detection (Suricata, model) exists; response is manual, section 6.
- **Blocking is simulated.** No firewall rule is changed. Control 5.26 is therefore reported as Partial.
- The lab has one analyst, so there is no independent second approver. This is a stated limitation, not a design choice.
- The procedure has been exercised only on scripted attacks from the lab's own attacker VM, never on a real incident.

## 2. Roles

| Role | Responsibility | Holder |
|---|---|---|
| Lab owner | Owns the procedure, the risk register and the SoA; approves changes | Hosni Nheri |
| Analyst | Triage, approve or decline in `analyst-approval`, write the decision record | Hosni Nheri |

Hosni Nheri holds every role: no other contributor works on this repository. This is a segregation-of-duties weakness, because the approver of the block is also the owner of the system. Record it in the gap analysis (Day 9). Compensating measure: each decision is logged in Shuffle with a timestamp and reviewed after the test session (step 6).

## 3. Event classification

| Class | Definition | Handling |
|---|---|---|
| Planned test | Source IP and time window match a run in `data/collection_log_clean.csv` | Record, no response needed, keep as evidence |
| Unplanned event | Alert or model score with no matching planned run | Triage under section 5 |
| Incident | Unplanned event confirmed as an attack, or a wrongful action (for example a wrong block) | Respond under section 5, then review under section 7 |

Severity for unplanned events follows the risk register scale (Low, Moderate, High). Proposed lab targets, not service levels: triage within 15 minutes of the alert while a test session is running.

## 4. Detection sources

| Scenario | Detection | Automated response | Risk |
|---|---|---|---|
| SSH brute force | Splunk alert (cron `*/5 * * * *`, last 5 minutes, throttle 10 min on `src_ip`), failure threshold as set in the saved search, plus ML score | Yes: webhook → Shuffle → score → enrichment → approval → simulated block | R-03 |
| Nmap SYN scan | Suricata rule 9000001 (20 SYNs in 5 s) and ML score | No | R-01 |
| Slow scan, low-and-slow brute force | Model only (Suricata thresholds miss these, see Day 5 report) | No | R-02 |
| FTP / HTTP brute force | Suricata rules 9000003 (FTP `530` replies, 5 in 60 s) / 9000004 (HTTP "Login failed" on :8080, 5 in 30 s) and ML score | No (`src_ip` unreliable for these protocols) | R-04 |
| Benign baseline | No alert expected | No | R-05 |

## 5. Procedure for an alert

### Step 0 — Preparation (before every test or monitoring period)
Control 8.15, risks R-08 and R-09.
1. Check that ingestion is alive: `latest(_time)` for the Suricata and auth indexes is recent. Stopped ingestion means alerts never fire.
2. Check that the Shuffle workflow is enabled and the FastAPI scoring service answers (health or test call).
3. Check that the tunnel to the scoring service and the Shuffle cloud webhook are open for the test only, and note the closing step in step 7. The Shuffle workflow runs in the cloud, so confirm that the cloud workflow can still reach the scoring service (a test call through the tunnel) and that the endpoint requires its API key.
4. Note the planned run (scenario, command, start time) in the collection log.

### Step 1 — Detect
The Splunk alert fires, or an analyst sees a Suricata alert or a model score above threshold. Evidence: `R-03_splunk_alert_to_shuffle.png`, `R-03_splunk_webhook_log.png`.

### Step 2 — Identify the event class
Compare source IP and time window with the collection log. Planned test: record and stop. Otherwise continue.

### Step 3 — Assess (control 5.25)
The analyst checks, in this order:
1. **Is `src_ip` plausible?** A wrong `src_ip` is the main cause of wrongful blocks (R-03). Check it against the lab address list in the Day 2 playbook:
   - `172.30.0.10` (`victim1`), the sensors, Splunk, Shuffle and the scoring service are **protected**: never an attacker.
   - `172.30.0.1` is the Kali host, which is **both the lab gateway and the current attack source**. Every scripted attack arrives from this address. It cannot go on a plain protected list, because that would reject all test attacks. It also means a real block of it would cut the victim network. This is why the block is simulated, and it is the concrete root of R-03. Treat any alert from `172.30.0.1` as a planned test (step 2) unless the collection log has no matching run.
   - Any other source address in `172.30.0.0/24` is unexpected: investigate before any decision.
   - Keep this address list in the repository. The open Day 2 follow-up (a dedicated attacker container with its own address) would remove the ambiguity and should be reflected in R-03 if done.
   - Ignore the stock rule `ET INFO Python BaseHTTP Server Banner` (sid 2034635): it fires on every request to the stand-in login server and is expected noise, not an event.
2. **Model output:** label and score against the threshold of 0.7. Evidence example: `R-03_fastapi_score_masque.png` (`ssh_bruteforce`, 0.985).
3. **Independent corroboration:** a Suricata alert, failed-login counts in the auth logs, or AbuseIPDB / VirusTotal enrichment. Lab addresses will usually have no reputation data, so a clean reputation does **not** clear an event in this lab.
4. **Known model confusion:** an `nmap -sV` session can look like HTTP brute force because it sends real HTTP requests (Day 5 report, section 3). To tell them apart, check whether requests spread over many ports (scan) or hit one endpoint repeatedly (brute force).

Proposed decision rule (confirm or change): approve only if `src_ip` is not protected **and** at least one signal besides the model agrees. Otherwise decline or investigate manually.

### Step 4 — Respond (control 5.26)
| Decision | Action | Evidence |
|---|---|---|
| Approve | `analyst-approval` continues; the block is simulated, no firewall change | `R-03_approval_continue.png` |
| Decline | Workflow aborts; no action | `R-03_decline_aborted.png` |
| Defer | Investigate manually, record the reason, and re-check in the next alert cycle | Decision record |

Real blocking is out of scope. Extending automation to FTP/HTTP is allowed only after the `src_ip` risk is solved (R-03 and R-04 treatments).

### Step 5 — Record (controls 5.25, 5.28)
Write one decision record per unplanned event. Shuffle logs hold the SSH approve/decline timestamp; the record adds the reasoning.

| Field | Content |
|---|---|
| Record ID, date and time | |
| Analyst | |
| Source IP (mask in public evidence) | |
| Scenario and detection source | |
| Model label and score, threshold used | |
| Suricata signature, if any | |
| Enrichment summary | |
| Decision (approve / decline / defer) and rationale | |
| Evidence files | `evidence/<matrix row>_<what>.png` |
| Linked risk ID | |

Evidence handling: name files by matrix row, mask the webhook URL, tunnel URL, API keys and private addresses before they leave the private repository, keep raw logs private.

### Step 6 — Review (control 5.27)
After each test session, or after any incident, answer briefly:
- Was the detection on time, and which layer caught it (Suricata, model, both)?
- Was the decision correct in hindsight? If not, which signal misled?
- Does a risk rating change? Update `risk_register.md` with the date.
- Does the model monitoring plan (Day 8) need a trigger: false-positive rate above threshold, a new missed attack type, a drift signal?
Lessons feed the gap analysis (Day 9).

### Step 7 — Close and clean up
Close or rotate the tunnel and webhook (R-09). Remember that alert content has been sent to the Shuffle cloud during the session. Confirm ingestion is still healthy. Archive evidence by matrix row.

## 6. Manual path for scenarios without automation
For scans and FTP/HTTP brute force: run steps 1 to 3 from the Suricata and model output in Splunk, decide, record (step 5), review (step 6). No block is attempted. Mark the record "detection only".

## 7. Procedure test record (fill in; this is the evidence for 5.24)
5.24 should be marked Implemented only after the procedure has been followed once end to end.

| Test | Date | Scenario | Steps followed | Gaps found | Result |
|---|---|---|---|---|---|
| Dry run 1 | | SSH brute force, approve | 0 to 7 | | |
| Dry run 2 | | SSH brute force, decline | 0 to 7 | | |
| Dry run 3 | | Slow scan, manual path | 0 to 3, 5, 6 | | |

## 8. Mapping

| Step | Control | Risks |
|---|---|---|
| 0 | 8.15, 5.24 | R-08, R-09 |
| 1 | 8.16 | R-01, R-02, R-03 |
| 3 | 5.25 | R-03, R-05 |
| 4 | 5.26 | R-03 |
| 5 | 5.25, 5.28 | R-03 |
| 6 | 5.27 | R-02, R-06 |

## 9. Review of this document
Review after any change to the Splunk alert, the Shuffle workflow, the model threshold or the lab topology. Date and change note: **[to fill]**.
